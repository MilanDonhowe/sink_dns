// Adblocker Plus file format parser for blocklists
// The rough specification for the format is: https://adblockplus.org/filter-cheatsheet#blocking2

use std::{collections::HashMap, path::PathBuf};
use sink_dns::BlockEntry;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Debug)]
pub enum AdblockParserError {
    MissingFile,
    FileReadingError
}

/*
    This is a pretty minimal parser.

    As far as I'm aware, we just need to parse: ||<domain>^ lines.
    There's some interesting meta data in the comments of some blocklists like (https://hagezi-mirror.dnsbunker.org/adblock/light.txt)
    relating to an "expires" field.

*/
pub fn parse_adp_file(blocklist_path: PathBuf) -> Result<HashMap<String, BlockEntry>, AdblockParserError> {
    let mut blocklist = HashMap::new();

    // avoided using fs::read_to_string since blocklists can be very large, and I want to preserve ram on user machine.
    let blocklist_file = File::open(blocklist_path).map_err(|_|AdblockParserError::MissingFile)?;
    let reader = BufReader::new(blocklist_file);

    for line in reader.lines(){
        let line = line.map_err(|_|AdblockParserError::FileReadingError)?;
        // remove whitespace
        let line = line.trim();
        if line.starts_with("||"){
            // get everything before the first ^
            if let Some(domain) = line.split_terminator("^").next() {
                // ignore first ||
                if let Some(domain) = domain.get(2..) {
                    blocklist.insert(domain.to_string(), BlockEntry::Block);
                }
            }
        }
    }

    Ok(blocklist)
}




