// module for the upstream DNS forwarding
// Involves its own worker pool management thus its own module file

use tokio::sync::mpsc::{self, Receiver, Sender, UnboundedReceiver, UnboundedSender};
use tokio_util::sync::CancellationToken;
use std::net::SocketAddr;
use tokio::net::{UdpSocket};
use tokio::time::timeout;
use std::time::Duration;
use tokio_util::task::TaskTracker;
use std::sync::{Arc};
use tokio::sync::Mutex;

// waits for msg in queue and then hits upstream
async fn dns_forward_worker(
    worker_close: CancellationToken,
    dns_response: Sender<(Vec<u8>, SocketAddr)>,
    dns_request: Arc<Mutex<Receiver<sink_dns::MSG>>>,
    upstream_dns_addr: String,
    worker_id: u32
){
    println!("{worker_id} spawned");
    loop {
        tokio::select! {
            mut dns_tx_queue = dns_request.lock() => {
                tokio::select! {
                    msg = dns_tx_queue.recv() => {
                        match msg {
                            Some((pkt, from_addr)) => {
                                println!("{worker_id} handling request");
                                let mut buf = vec![0;600]; // a few more bytes than needed
                                
                                // create random address
                                let upstream_dns = UdpSocket::bind("0.0.0.0:0").await;

                                let upstream_dns = match upstream_dns {
                                    Ok(dns) => dns,
                                    Err(e) => {
                                        eprintln!("[x] FAILED to create socket for upstream DNS connection: {}", e);
                                        return;
                                    }
                                };

                                // udp is connection less but this call restricts our socket to the referenced address
                                // this has some performance benefits as opposed to multiple send_to + recv_from calls
                                let connect_result = upstream_dns.connect(&upstream_dns_addr).await;
                                match connect_result {
                                    Ok(_) => {},
                                    Err(e) => {
                                        eprintln!("[x] FAILED to connect to upstream DNS: {:?}", e);
                                        return;
                                    }
                                }

                                // ignore errors
                                /*
                                    I do not think this select! is necessary as dns is fire+forget.
                                */
                                tokio::select! {
                                    dns_send = upstream_dns.send(&pkt) => {
                                        match dns_send {
                                            Ok(_) => {},
                                            Err(e) => {
                                                eprintln!("[x] FAILED to send msg to upstream DNS: {:?}", e);
                                                return;
                                            }
                                        }
                                    },
                                    _ = worker_close.cancelled() => {
                                        return;
                                    }
                                }

                                tokio::select! {
                                    dns_reply = timeout(Duration::from_secs(3), upstream_dns.recv(&mut buf)) => {
                                        match dns_reply {
                                            Ok(Ok(msg_len)) => {
                                                // ignore error for now
                                                println!("[*] sending dns reply back to stub resolver");
                                                let _ = dns_response.send(( buf[0..msg_len].to_vec(), from_addr)).await;
                                            }
                                            // socket I/O error
                                            Ok(Err(e)) => {
                                                eprintln!("[x] I/O error trying to recieve msg from upstream DNS: {e}");
                                            }
                                            Err(_) => {
                                                eprintln!("[x] Timeout waiting to recieve response from upstream DNS");
                                            }
                                        }
                                    },
                                    // ensure we gracefully exit
                                    _ = worker_close.cancelled() => {}
                                }


                            },
                            None => {}
                        }
                    },
                    _ = worker_close.cancelled() => {}
                }
            },
            // exit if token closes
            _ = worker_close.cancelled() => {
                break;
            }
        }
    }

}


pub async fn dns_forwarder(
    upstream_dns: String,
    mut dns_traffic_rx: Receiver<sink_dns::MSG>,
    dns_response_tx: Sender<(Vec<u8>, SocketAddr)>,
    dns_close_token: CancellationToken
) {
    let upstream_dns_addr = upstream_dns;
    let tracker = TaskTracker::new();

    let dns_msg_recv = Arc::new(Mutex::new(dns_traffic_rx));

    let thread_pool = 5;
    for _thread in 0..thread_pool {
        let close_token = dns_close_token.clone();
        let dns_tx = dns_response_tx.clone();
        let dns_rx = Arc::clone(&dns_msg_recv);
        let dns_addr: String = upstream_dns_addr.clone();
        tracker.spawn(async move {
            dns_forward_worker(close_token, dns_tx, dns_rx, dns_addr, _thread).await;
        });
    }

    tokio::select! {
        _ = dns_close_token.cancelled() => {
            tracker.close();
            println!("[*] waiting for tracker to close");
            let _ = tracker.wait().await;
        }
    }
}


