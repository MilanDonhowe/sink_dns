use sink_dns::{BlockEntry, process_dns_packet};
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::net::{UdpSocket};
use tokio::signal;
use tokio::sync::mpsc::{self, Receiver, Sender, UnboundedReceiver, UnboundedSender};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use clap::Parser;

/// small dns sinkhole
#[derive(Parser,Debug)]
struct Args {
    /// Upstream dns server to forward unsunk DNS requests
    #[arg(short, long, default_value_t = "8.8.8.8:53".to_string())]
    upstream_dns: String,

    #[arg(short, long, value_name = "FILE", default_value_os_t=PathBuf::from(r"blocklist.txt"))]
    blocklist: PathBuf
}


#[tokio::main]
async fn main() {
    // cli
    let args = Args::parse();

    let blocklist_path = args.blocklist;
    let upstream_dns = args.upstream_dns;

    // 1. synchronous bootstrap
    println!("[*] synchronously loading blocklist from {}", blocklist_path.display());
    let mut block_list: HashMap<String, BlockEntry> = HashMap::new();
    fs::read_to_string(blocklist_path)
        .expect("[x] could not read blocklist file")
        .lines()
        .for_each(|domain| {
            block_list.insert(domain.to_string(), BlockEntry::Block);
        });

    let tracker = TaskTracker::new();

    let server = UdpSocket::bind("127.0.0.1:7753")
        .await
        .expect("port occupied");

    // broadcast shutdown from task
    let (tx_shutdown, mut rx_shutdown): (UnboundedSender<()>, UnboundedReceiver<()>) =
        mpsc::unbounded_channel();

    // spawn server task
    let close_token = CancellationToken::new();

    // for real DNS traffic we forward it
    let (dns_traffic_tx, mut dns_traffic_rx): (Sender<sink_dns::MSG>, Receiver<sink_dns::MSG>) =
        mpsc::channel(64);
    let (dns_response_tx, mut dns_response_rx): (Sender<sink_dns::MSG>, Receiver<sink_dns::MSG>) =
        mpsc::channel(64);

    let dns_close_token = close_token.clone();
    let df_dns_response_tx: Sender<(Vec<u8>, SocketAddr)> = dns_response_tx.clone();

    let dns_forwarder_task = tokio::spawn(async move {
        // TODO: make the upstream dns configurable
        let upstream_dns_addr = upstream_dns;

        let mut buf = vec![0; 1024];
        loop {
            
            tokio::select! {
                msg = dns_traffic_rx.recv() => {
                    match msg {
                        Some((pkt, from_addr)) => {
                            println!("[*] sending payload to upstream dns");
                            let send_response = df_dns_response_tx.clone();
                            let upstream_dns_addr = upstream_dns_addr.clone();
                            let task_cancel = dns_close_token.clone();
                            tracker.spawn(async move {
                                /* 
                                    TODO: I need some time out mechanism here so we don't exhaust the OS's total fd count on these udp sockets.
                                */
                                // create socket
                                let mut buf = vec![0;600]; // a few more bytes than needed
                                
                                // create arndom address
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
                                let connect_result = upstream_dns.connect(upstream_dns_addr).await;
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
                                    _ = task_cancel.cancelled() => {
                                        return;
                                    }
                                }
                                //let dns_send = upstream_dns.send(&pkt).await;

                                tokio::select! {
                                    dns_reply = upstream_dns.recv(&mut buf) => {
                                        match dns_reply {
                                            Ok(msg_len) => {
                                                // ignore error for now
                                                println!("[*] sending dns reply back to stub resolver");
                                                let _ = send_response.send(( buf[0..msg_len].to_vec(), from_addr )).await;
                                            }
                                            Err(_) => {
                                                eprintln!("[x] FAILED to recieve msg from upstream DNS");
                                            }
                                        }
                                    },
                                    // ensure we gracefully exit
                                    _ = task_cancel.cancelled() => {}
                                }
                                
                            });
                        },
                        None => {}
                    }
                },
                _ = dns_close_token.cancelled() => {
                    tracker.close();
                    println!("[*] waiting for tracker to close");
                    let _ = tracker.wait().await;
                    break;
                }
            }
        }
    });

    let forward_to_dns_server = dns_traffic_tx.clone();
    let send_to_client = dns_response_tx.clone();
    let server_close_token = close_token.clone();
    let server_task = tokio::spawn(async move {
        // how do I loop here while respecting the close token and tx_shutdown?
        let mut buf = vec![0; 1024];
        loop {
            tokio::select! {
                // inbound DNS query
                result = server.recv_from(&mut buf) => {
                    // we do not care so much about contents yet
                    match result {
                        Ok((len, addr)) => {
                            // handle DNS query packet
                            println!("got request!");
                            let _ = process_dns_packet(&buf[0..len], addr, &block_list, &forward_to_dns_server, &send_to_client).await;
                        },
                        Err(_) => {
                            // signal shutdown
                            _ = tx_shutdown.send(());
                        }
                    }

                },
                // outbound real dns response back to dns stub client
                outbound_msg = dns_response_rx.recv() => {
                    match outbound_msg {
                        Some((msg, client_addr)) => {
                            let _ = server.send_to(&msg, client_addr).await;
                        },
                        None => {}
                    }

                },

                _ = server_close_token.cancelled() => {
                    break
                }
            }
        }
    });

    println!("[*] Spun up server");

    // graceful shutdown
    tokio::select! {
        _ = signal::ctrl_c() => {},
        _ = rx_shutdown.recv() => {}
    }

    println!("[*] Gracefully shutting down");

    close_token.cancel();

    // wait for tasks to shutdown
    println!("[*] waiting for server_task");
    let _ = server_task.await;

    println!("[*] waiting for dns_forwarder_task");
    let _ = dns_forwarder_task.await;



}
