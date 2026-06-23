use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::ExitCode;

use keystone_btc_proof::bundle::{
    CheckpointRecord, ClaimBundle, InMemoryCheckpointRegistry, InMemoryKeyRegistry, MerkleProof,
};
use keystone_btc_proof::order::{
    derive_script_and_commitment, Address, B256, BtcNetwork, Order, OrderPreimage, U256,
};
use keystone_btc_proof::taproot::Xpub;
use keystone_btc_proof::{
    evaluate_claim_bundle, sha256d, H256Internal, L2Context, OutPoint, Settlement, Transaction,
    TxIn, TxOut,
};
use serde::{Deserialize, Serialize};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("verify") => {
            let path = args.next();
            if args.next().is_some() {
                return Err("usage: keystone-btc-proof verify [request.json|-]".into());
            }
            let raw = read_input(path.as_deref())?;
            let request: VerifyRequest =
                serde_json::from_str(&raw).map_err(|e| format!("invalid JSON: {e}"))?;
            let input = request.try_into_runtime()?;
            let settlement = evaluate_claim_bundle(
                &input.claim_bundle,
                &input.keys,
                &input.checkpoints,
                &input.l2_context,
            )
            .map_err(|e| format!("verification failed: {}", e.challenge_reason().as_str()))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&SettlementJson::from_runtime(&settlement))
                    .map_err(|e| format!("failed to render JSON: {e}"))?
            );
            Ok(())
        }
        Some("template") => {
            if args.next().is_some() {
                return Err("usage: keystone-btc-proof template".into());
            }
            let template = VerifyRequest::sample()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&template)
                    .map_err(|e| format!("failed to render JSON: {e}"))?
            );
            Ok(())
        }
        Some("serve") => {
            let addr = args.next().unwrap_or_else(|| "0.0.0.0:8080".into());
            if args.next().is_some() {
                return Err("usage: keystone-btc-proof serve [host:port]".into());
            }
            serve_http(&addr)
        }
        Some("help") | Some("--help") | Some("-h") | None => {
            print_help();
            Ok(())
        }
        Some(cmd) => Err(format!("unknown command `{cmd}`")),
    }
}

fn print_help() {
    println!(
        "\
keystone-btc-proof

Commands:
  template               Print a valid sample verification request as JSON
  verify [file|-]        Verify a claim bundle from JSON (default: stdin)
  serve [host:port]      Serve a mobile-friendly browser UI (default 0.0.0.0:8080)
  help                   Show this help
"
    );
}

fn read_input(path: Option<&str>) -> Result<String, String> {
    match path {
        None | Some("-") => {
            let mut buf = String::new();
            io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| format!("failed to read stdin: {e}"))?;
            Ok(buf)
        }
        Some(path) => fs::read_to_string(path).map_err(|e| format!("failed to read `{path}`: {e}")),
    }
}

fn serve_http(addr: &str) -> Result<(), String> {
    let listener = TcpListener::bind(addr).map_err(|e| format!("failed to bind `{addr}`: {e}"))?;
    println!("keystone-btc-proof web UI listening on http://{addr}");
    println!("Open this address from your phone browser using the VPS IP and this port.");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(err) = handle_http_client(stream) {
                    eprintln!("request error: {err}");
                }
            }
            Err(err) => eprintln!("accept error: {err}"),
        }
    }
    Ok(())
}

fn handle_http_client(mut stream: TcpStream) -> Result<(), String> {
    let request = read_http_request(&mut stream)?;
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") => write_http_response(
            &mut stream,
            "200 OK",
            "text/html; charset=utf-8",
            render_index_html().as_bytes(),
        ),
        ("GET", "/api/sample") => {
            let sample = VerifyRequest::sample()?;
            let body = serde_json::to_vec_pretty(&sample)
                .map_err(|e| format!("failed to encode sample JSON: {e}"))?;
            write_api_response(&mut stream, "200 OK", &body)
        }
        ("OPTIONS", "/api/verify") => write_http_response_with_headers(
            &mut stream,
            "204 No Content",
            "text/plain; charset=utf-8",
            b"",
            api_cors_headers(),
        ),
        ("POST", "/api/verify") => {
            match serde_json::from_slice::<VerifyRequest>(&request.body) {
                Ok(request) => match request.try_into_runtime() {
                    Ok(input) => match evaluate_claim_bundle(
                        &input.claim_bundle,
                        &input.keys,
                        &input.checkpoints,
                        &input.l2_context,
                    ) {
                        Ok(settlement) => {
                            let body = serde_json::to_vec_pretty(&ApiVerifyResponse::ok(settlement))
                                .map_err(|e| format!("failed to encode response JSON: {e}"))?;
                            write_api_response(&mut stream, "200 OK", &body)
                        }
                        Err(err) => {
                            let body = serde_json::to_vec_pretty(&ApiVerifyResponse::err(err))
                                .map_err(|e| format!("failed to encode error JSON: {e}"))?;
                            write_api_response(
                                &mut stream,
                                "422 Unprocessable Entity",
                                &body,
                            )
                        }
                    },
                    Err(err) => {
                        let body = serde_json::to_vec_pretty(&ApiVerifyResponse::bad_request(err))
                            .map_err(|e| format!("failed to encode error JSON: {e}"))?;
                        write_api_response(&mut stream, "400 Bad Request", &body)
                    }
                },
                Err(err) => {
                    let body = serde_json::to_vec_pretty(&ApiVerifyResponse::bad_request(format!(
                        "invalid JSON body: {err}"
                    )))
                    .map_err(|e| format!("failed to encode error JSON: {e}"))?;
                    write_api_response(&mut stream, "400 Bad Request", &body)
                }
            }
        }
        _ => write_http_response(
            &mut stream,
            "404 Not Found",
            "text/plain; charset=utf-8",
            b"not found",
        ),
    }
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest, String> {
    let mut buf = Vec::with_capacity(8192);
    let mut header_end = None;
    loop {
        let mut chunk = [0u8; 1024];
        let n = stream
            .read(&mut chunk)
            .map_err(|e| format!("failed to read request: {e}"))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
            header_end = Some(pos + 4);
            break;
        }
        if buf.len() > 1024 * 1024 {
            return Err("request headers too large".into());
        }
    }

    let header_end = header_end.ok_or("incomplete HTTP headers")?;
    let head = String::from_utf8(buf[..header_end].to_vec())
        .map_err(|e| format!("request is not valid UTF-8: {e}"))?;
    let mut lines = head.split("\r\n").filter(|line| !line.is_empty());
    let request_line = lines.next().ok_or("missing request line")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or("missing method")?.to_string();
    let path = parts.next().ok_or("missing path")?.to_string();

    let mut content_length = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value
                    .trim()
                    .parse::<usize>()
                    .map_err(|e| format!("invalid content-length: {e}"))?;
            }
        }
    }
    if content_length > 2 * 1024 * 1024 {
        return Err("request body too large".into());
    }

    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let mut chunk = vec![0u8; content_length - body.len()];
        let n = stream
            .read(&mut chunk)
            .map_err(|e| format!("failed to read request body: {e}"))?;
        if n == 0 {
            return Err("unexpected EOF in request body".into());
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);

    Ok(HttpRequest { method, path, body })
}

fn write_http_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> Result<(), String> {
    write_http_response_with_headers(stream, status, content_type, body, &[])
}

fn write_api_response(stream: &mut TcpStream, status: &str, body: &[u8]) -> Result<(), String> {
    write_http_response_with_headers(
        stream,
        status,
        "application/json",
        body,
        api_cors_headers(),
    )
}

fn write_http_response_with_headers(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
    extra_headers: &[(&str, &str)],
) -> Result<(), String> {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len(),
    );
    stream.write_all(header.as_bytes()).map_err(|e| format!("failed to write response: {e}"))?;
    for (name, value) in extra_headers {
        let line = format!("{name}: {value}\r\n");
        stream
            .write_all(line.as_bytes())
            .map_err(|e| format!("failed to write response: {e}"))?;
    }
    stream
        .write_all(b"\r\n")
        .and_then(|_| stream.write_all(body))
        .map_err(|e| format!("failed to write response: {e}"))
}

fn api_cors_headers() -> &'static [(&'static str, &'static str)] {
    &[
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
        ("Access-Control-Allow-Headers", "Content-Type"),
    ]
}

fn render_index_html() -> String {
    INDEX_HTML.to_string()
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

#[derive(Debug, Serialize)]
struct ApiVerifyResponse {
    ok: bool,
    settlement: Option<SettlementJson>,
    error: Option<ApiErrorJson>,
}

impl ApiVerifyResponse {
    fn ok(settlement: Settlement) -> Self {
        Self {
            ok: true,
            settlement: Some(SettlementJson::from_runtime(&settlement)),
            error: None,
        }
    }

    fn err(err: keystone_btc_proof::ClaimError) -> Self {
        Self {
            ok: false,
            settlement: None,
            error: Some(ApiErrorJson {
                reason: err.challenge_reason().as_str().to_string(),
                message: format!("{err:?}"),
            }),
        }
    }

    fn bad_request(message: String) -> Self {
        Self {
            ok: false,
            settlement: None,
            error: Some(ApiErrorJson {
                reason: "BadRequest".to_string(),
                message,
            }),
        }
    }
}

#[derive(Debug, Serialize)]
struct ApiErrorJson {
    reason: String,
    message: String,
}

struct RuntimeInput {
    claim_bundle: ClaimBundle,
    keys: InMemoryKeyRegistry,
    checkpoints: InMemoryCheckpointRegistry,
    l2_context: L2Context,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VerifyRequest {
    claim_bundle: ClaimBundleJson,
    keys: Vec<KeyEntryJson>,
    checkpoints: Vec<CheckpointEntryJson>,
    l2_context: L2ContextJson,
}

impl VerifyRequest {
    fn try_into_runtime(self) -> Result<RuntimeInput, String> {
        let mut keys = InMemoryKeyRegistry::new();
        for entry in self.keys {
            keys.insert(entry.key_id.parse_b256("keys[].key_id")?, entry.xpub.try_into_runtime()?);
        }

        let mut checkpoints = InMemoryCheckpointRegistry::new();
        for entry in self.checkpoints {
            checkpoints.insert(entry.checkpoint_id.parse_b256("checkpoints[].checkpoint_id")?, entry.record.try_into_runtime()?);
        }

        Ok(RuntimeInput {
            claim_bundle: self.claim_bundle.try_into_runtime()?,
            keys,
            checkpoints,
            l2_context: self.l2_context.try_into_runtime(),
        })
    }

    fn sample() -> Result<Self, String> {
        let preimage = OrderPreimage {
            solver: [1u8; 20],
            recipient: [2u8; 20],
            btc_network: BtcNetwork::Regtest,
            solver_btc_key_id: [4u8; 32],
            amount_sat: 50_000,
            destination_token: [5u8; 20],
            destination_amount: U256::from_u128(123_456),
            min_confirmations: 1,
            max_btc_inclusion_height: 1_000,
            quote_expires_at_l2: 10,
            claim_deadline_l2: 20,
            reclaim_after_l2: 30,
            max_destination_amount_cap: U256::from_u128(123_456),
            replay_domain: [6u8; 32],
            nonce: [7u8; 32],
        };
        let xpub = Xpub {
            public_key: decode_hex_array::<33>(
                "sample xpub public key",
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            )?,
            chain_code: [7u8; 32],
        };
        let mut keys = InMemoryKeyRegistry::new();
        keys.insert(preimage.solver_btc_key_id, xpub.clone());
        let (script_pubkey, commitment) =
            derive_script_and_commitment(&preimage, &keys).map_err(|_| "failed to derive sample script".to_string())?;
        let order = Order {
            order_id: preimage.order_id(),
            preimage: preimage.clone(),
            btc_script_pubkey_commitment: commitment,
        };
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                prev: OutPoint {
                    txid: [3u8; 32],
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xffff_fffe,
            }],
            outputs: vec![TxOut {
                value_sat: 75_000,
                script_pubkey: script_pubkey.to_vec(),
            }],
            witnesses: None,
            lock_time: 0,
        };
        let raw_tx = tx.wire_serialize();
        let txid_internal = tx.txid_internal().0;
        let checkpoint_hash = [9u8; 32];
        let checkpoint_height = 100;
        let checkpoint_nbits = 0x207f_ffff;
        let header = mine_header(checkpoint_hash, txid_internal, checkpoint_nbits)?;
        let tip_hash = sha256d(&header);

        Ok(Self {
            claim_bundle: ClaimBundleJson::from_runtime(&ClaimBundle {
                order,
                txid_internal,
                raw_tx,
                vout: 0,
                merkle_proof: MerkleProof {
                    tx_index: 0,
                    siblings: vec![],
                    total_transactions: 1,
                },
                tx_block_index: 0,
                checkpoint_id: [1u8; 32],
                checkpoint_height,
                checkpoint_hash,
                confirmation_headers: vec![header],
                claimed_tip_height: checkpoint_height + 1,
                claimed_tip_hash: tip_hash,
            }),
            keys: vec![KeyEntryJson {
                key_id: Hex32::from_bytes(&preimage.solver_btc_key_id),
                xpub: XpubJson::from_runtime(&xpub),
            }],
            checkpoints: vec![
                CheckpointEntryJson {
                    checkpoint_id: Hex32::from_bytes(&[1u8; 32]),
                    record: CheckpointRecordJson::from_runtime(&CheckpointRecord {
                        network: BtcNetwork::Regtest,
                        height: checkpoint_height,
                        hash: checkpoint_hash,
                        nbits: checkpoint_nbits,
                    }),
                },
                CheckpointEntryJson {
                    checkpoint_id: Hex32::from_bytes(&[2u8; 32]),
                    record: CheckpointRecordJson::from_runtime(&CheckpointRecord {
                        network: BtcNetwork::Regtest,
                        height: checkpoint_height + 1,
                        hash: tip_hash,
                        nbits: checkpoint_nbits,
                    }),
                },
            ],
            l2_context: L2ContextJson { now_l2: 15 },
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClaimBundleJson {
    order: OrderJson,
    txid_internal: Hex32,
    raw_tx: HexBytes,
    vout: u32,
    merkle_proof: MerkleProofJson,
    tx_block_index: u32,
    checkpoint_id: Hex32,
    checkpoint_height: u32,
    checkpoint_hash: Hex32,
    confirmation_headers: Vec<Hex80>,
    claimed_tip_height: u32,
    claimed_tip_hash: Hex32,
}

impl ClaimBundleJson {
    fn try_into_runtime(self) -> Result<ClaimBundle, String> {
        Ok(ClaimBundle {
            order: self.order.try_into_runtime()?,
            txid_internal: self.txid_internal.parse_b256("claim_bundle.txid_internal")?,
            raw_tx: self.raw_tx.parse_vec("claim_bundle.raw_tx")?,
            vout: self.vout,
            merkle_proof: self.merkle_proof.try_into_runtime()?,
            tx_block_index: self.tx_block_index,
            checkpoint_id: self.checkpoint_id.parse_b256("claim_bundle.checkpoint_id")?,
            checkpoint_height: self.checkpoint_height,
            checkpoint_hash: self.checkpoint_hash.parse_b256("claim_bundle.checkpoint_hash")?,
            confirmation_headers: self
                .confirmation_headers
                .into_iter()
                .map(|h| h.parse_header("claim_bundle.confirmation_headers[]"))
                .collect::<Result<Vec<_>, _>>()?,
            claimed_tip_height: self.claimed_tip_height,
            claimed_tip_hash: self.claimed_tip_hash.parse_b256("claim_bundle.claimed_tip_hash")?,
        })
    }

    fn from_runtime(value: &ClaimBundle) -> Self {
        Self {
            order: OrderJson::from_runtime(&value.order),
            txid_internal: Hex32::from_bytes(&value.txid_internal),
            raw_tx: HexBytes::from_bytes(&value.raw_tx),
            vout: value.vout,
            merkle_proof: MerkleProofJson::from_runtime(&value.merkle_proof),
            tx_block_index: value.tx_block_index,
            checkpoint_id: Hex32::from_bytes(&value.checkpoint_id),
            checkpoint_height: value.checkpoint_height,
            checkpoint_hash: Hex32::from_bytes(&value.checkpoint_hash),
            confirmation_headers: value
                .confirmation_headers
                .iter()
                .map(Hex80::from_header)
                .collect(),
            claimed_tip_height: value.claimed_tip_height,
            claimed_tip_hash: Hex32::from_bytes(&value.claimed_tip_hash),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OrderJson {
    order_id: Hex32,
    preimage: OrderPreimageJson,
    btc_script_pubkey_commitment: Hex32,
}

impl OrderJson {
    fn try_into_runtime(self) -> Result<Order, String> {
        Ok(Order {
            order_id: self.order_id.parse_b256("claim_bundle.order.order_id")?,
            preimage: self.preimage.try_into_runtime()?,
            btc_script_pubkey_commitment: self
                .btc_script_pubkey_commitment
                .parse_b256("claim_bundle.order.btc_script_pubkey_commitment")?,
        })
    }

    fn from_runtime(value: &Order) -> Self {
        Self {
            order_id: Hex32::from_bytes(&value.order_id),
            preimage: OrderPreimageJson::from_runtime(&value.preimage),
            btc_script_pubkey_commitment: Hex32::from_bytes(&value.btc_script_pubkey_commitment),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OrderPreimageJson {
    solver: Hex20,
    recipient: Hex20,
    btc_network: NetworkJson,
    solver_btc_key_id: Hex32,
    amount_sat: u64,
    destination_token: Hex20,
    destination_amount: Hex32,
    min_confirmations: u32,
    max_btc_inclusion_height: u32,
    quote_expires_at_l2: u64,
    claim_deadline_l2: u64,
    reclaim_after_l2: u64,
    max_destination_amount_cap: Hex32,
    replay_domain: Hex32,
    nonce: Hex32,
}

impl OrderPreimageJson {
    fn try_into_runtime(self) -> Result<OrderPreimage, String> {
        Ok(OrderPreimage {
            solver: self.solver.parse_address("claim_bundle.order.preimage.solver")?,
            recipient: self.recipient.parse_address("claim_bundle.order.preimage.recipient")?,
            btc_network: self.btc_network.try_into_runtime()?,
            solver_btc_key_id: self
                .solver_btc_key_id
                .parse_b256("claim_bundle.order.preimage.solver_btc_key_id")?,
            amount_sat: self.amount_sat,
            destination_token: self
                .destination_token
                .parse_address("claim_bundle.order.preimage.destination_token")?,
            destination_amount: U256(
                self.destination_amount
                    .parse_b256("claim_bundle.order.preimage.destination_amount")?,
            ),
            min_confirmations: self.min_confirmations,
            max_btc_inclusion_height: self.max_btc_inclusion_height,
            quote_expires_at_l2: self.quote_expires_at_l2,
            claim_deadline_l2: self.claim_deadline_l2,
            reclaim_after_l2: self.reclaim_after_l2,
            max_destination_amount_cap: U256(
                self.max_destination_amount_cap
                    .parse_b256("claim_bundle.order.preimage.max_destination_amount_cap")?,
            ),
            replay_domain: self
                .replay_domain
                .parse_b256("claim_bundle.order.preimage.replay_domain")?,
            nonce: self.nonce.parse_b256("claim_bundle.order.preimage.nonce")?,
        })
    }

    fn from_runtime(value: &OrderPreimage) -> Self {
        Self {
            solver: Hex20::from_bytes(&value.solver),
            recipient: Hex20::from_bytes(&value.recipient),
            btc_network: NetworkJson::from_runtime(value.btc_network),
            solver_btc_key_id: Hex32::from_bytes(&value.solver_btc_key_id),
            amount_sat: value.amount_sat,
            destination_token: Hex20::from_bytes(&value.destination_token),
            destination_amount: Hex32::from_bytes(&value.destination_amount.0),
            min_confirmations: value.min_confirmations,
            max_btc_inclusion_height: value.max_btc_inclusion_height,
            quote_expires_at_l2: value.quote_expires_at_l2,
            claim_deadline_l2: value.claim_deadline_l2,
            reclaim_after_l2: value.reclaim_after_l2,
            max_destination_amount_cap: Hex32::from_bytes(&value.max_destination_amount_cap.0),
            replay_domain: Hex32::from_bytes(&value.replay_domain),
            nonce: Hex32::from_bytes(&value.nonce),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum NetworkJson {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

impl NetworkJson {
    fn try_into_runtime(self) -> Result<BtcNetwork, String> {
        Ok(match self {
            NetworkJson::Mainnet => BtcNetwork::Mainnet,
            NetworkJson::Testnet => BtcNetwork::Testnet,
            NetworkJson::Signet => BtcNetwork::Signet,
            NetworkJson::Regtest => BtcNetwork::Regtest,
        })
    }

    fn from_runtime(value: BtcNetwork) -> Self {
        match value {
            BtcNetwork::Mainnet => NetworkJson::Mainnet,
            BtcNetwork::Testnet => NetworkJson::Testnet,
            BtcNetwork::Signet => NetworkJson::Signet,
            BtcNetwork::Regtest => NetworkJson::Regtest,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MerkleProofJson {
    tx_index: u32,
    siblings: Vec<Hex32>,
    total_transactions: u32,
}

impl MerkleProofJson {
    fn try_into_runtime(self) -> Result<MerkleProof, String> {
        Ok(MerkleProof {
            tx_index: self.tx_index,
            siblings: self
                .siblings
                .into_iter()
                .map(|s| s.parse_b256("claim_bundle.merkle_proof.siblings[]"))
                .collect::<Result<Vec<_>, _>>()?,
            total_transactions: self.total_transactions,
        })
    }

    fn from_runtime(value: &MerkleProof) -> Self {
        Self {
            tx_index: value.tx_index,
            siblings: value.siblings.iter().map(Hex32::from_bytes).collect(),
            total_transactions: value.total_transactions,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyEntryJson {
    key_id: Hex32,
    xpub: XpubJson,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct XpubJson {
    public_key: Hex33,
    chain_code: Hex32,
}

impl XpubJson {
    fn try_into_runtime(self) -> Result<Xpub, String> {
        Ok(Xpub {
            public_key: self.xpub_public_key()?,
            chain_code: self.chain_code.parse_b256("keys[].xpub.chain_code")?,
        })
    }

    fn xpub_public_key(&self) -> Result<[u8; 33], String> {
        self.public_key.parse_pubkey("keys[].xpub.public_key")
    }

    fn from_runtime(value: &Xpub) -> Self {
        Self {
            public_key: Hex33::from_bytes(&value.public_key),
            chain_code: Hex32::from_bytes(&value.chain_code),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CheckpointEntryJson {
    checkpoint_id: Hex32,
    record: CheckpointRecordJson,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CheckpointRecordJson {
    network: NetworkJson,
    height: u32,
    hash: Hex32,
    nbits: u32,
}

impl CheckpointRecordJson {
    fn try_into_runtime(self) -> Result<CheckpointRecord, String> {
        Ok(CheckpointRecord {
            network: self.network.try_into_runtime()?,
            height: self.height,
            hash: self.hash.parse_b256("checkpoints[].record.hash")?,
            nbits: self.nbits,
        })
    }

    fn from_runtime(value: &CheckpointRecord) -> Self {
        Self {
            network: NetworkJson::from_runtime(value.network),
            height: value.height,
            hash: Hex32::from_bytes(&value.hash),
            nbits: value.nbits,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct L2ContextJson {
    now_l2: u64,
}

impl L2ContextJson {
    fn try_into_runtime(self) -> L2Context {
        L2Context {
            now_l2: self.now_l2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SettlementJson {
    order_id: Hex32,
    txid_internal: Hex32,
    recipient: Hex20,
    destination_token: Hex20,
    destination_amount: Hex32,
    amount_paid_sat: u64,
    block_height: u32,
    confirmations: u32,
}

impl SettlementJson {
    fn from_runtime(value: &Settlement) -> Self {
        Self {
            order_id: Hex32::from_bytes(&value.order_id),
            txid_internal: Hex32::from_bytes(&value.txid_internal),
            recipient: Hex20::from_bytes(&value.recipient),
            destination_token: Hex20::from_bytes(&value.destination_token),
            destination_amount: Hex32::from_bytes(&value.destination_amount.0),
            amount_paid_sat: value.amount_paid_sat,
            block_height: value.block_height,
            confirmations: value.confirmations,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
struct HexBytes(String);

impl HexBytes {
    fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(bytes))
    }

    fn parse_vec(&self, field: &str) -> Result<Vec<u8>, String> {
        decode_hex_vec(field, &self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
struct Hex20(String);

impl Hex20 {
    fn from_bytes(bytes: &Address) -> Self {
        Self(hex::encode(bytes))
    }

    fn parse_address(&self, field: &str) -> Result<Address, String> {
        decode_hex_array::<20>(field, &self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
struct Hex32(String);

impl Hex32 {
    fn from_bytes(bytes: &B256) -> Self {
        Self(hex::encode(bytes))
    }

    fn parse_b256(&self, field: &str) -> Result<B256, String> {
        decode_hex_array::<32>(field, &self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
struct Hex33(String);

impl Hex33 {
    fn from_bytes(bytes: &[u8; 33]) -> Self {
        Self(hex::encode(bytes))
    }

    fn parse_pubkey(&self, field: &str) -> Result<[u8; 33], String> {
        decode_hex_array::<33>(field, &self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
struct Hex80(String);

impl Hex80 {
    fn from_header(bytes: &[u8; 80]) -> Self {
        Self(hex::encode(bytes))
    }

    fn parse_header(&self, field: &str) -> Result<[u8; 80], String> {
        decode_hex_array::<80>(field, &self.0)
    }
}

fn decode_hex_vec(field: &str, value: &str) -> Result<Vec<u8>, String> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    hex::decode(trimmed).map_err(|e| format!("{field}: invalid hex: {e}"))
}

fn decode_hex_array<const N: usize>(field: &str, value: &str) -> Result<[u8; N], String> {
    let bytes = decode_hex_vec(field, value)?;
    if bytes.len() != N {
        return Err(format!(
            "{field}: expected {N} bytes, got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn mine_header(
    prev_block: H256Internal,
    merkle_root: H256Internal,
    nbits: u32,
) -> Result<[u8; 80], String> {
    let mut header = [0u8; 80];
    header[..4].copy_from_slice(&2i32.to_le_bytes());
    header[4..36].copy_from_slice(&prev_block);
    header[36..68].copy_from_slice(&merkle_root);
    header[68..72].copy_from_slice(&1_700_000_000u32.to_le_bytes());
    header[72..76].copy_from_slice(&nbits.to_le_bytes());
    for nonce in 0..u32::MAX {
        header[76..80].copy_from_slice(&nonce.to_le_bytes());
        if keystone_btc_proof::pow::check_pow_with_expected_nbits(&header, nbits).is_ok() {
            return Ok(header);
        }
    }
    Err("failed to mine sample header".into())
}

const INDEX_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Keystone BTC Proof</title>
  <style>
    :root {
      --bg: #f4efe6;
      --ink: #1f1a17;
      --panel: #fffaf2;
      --line: #dbcdb8;
      --accent: #0f766e;
      --accent-2: #c2410c;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Georgia, "Times New Roman", serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top right, rgba(194,65,12,.14), transparent 28%),
        radial-gradient(circle at left center, rgba(15,118,110,.12), transparent 24%),
        var(--bg);
    }
    .shell {
      max-width: 960px;
      margin: 0 auto;
      padding: 24px 16px 48px;
    }
    .hero, .panel {
      background: rgba(255,250,242,.92);
      backdrop-filter: blur(4px);
      border: 1px solid var(--line);
      border-radius: 18px;
      box-shadow: 0 14px 40px rgba(31,26,23,.08);
    }
    .hero {
      padding: 20px;
      margin-bottom: 16px;
    }
    .hero h1 {
      margin: 0 0 8px;
      font-size: clamp(28px, 4vw, 42px);
      line-height: 1;
    }
    .hero p {
      margin: 0;
      max-width: 60ch;
      font-size: 16px;
    }
    .grid {
      display: grid;
      gap: 16px;
    }
    .panel {
      padding: 16px;
    }
    .row {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center;
      margin-bottom: 12px;
    }
    .badge {
      display: inline-block;
      padding: 6px 10px;
      border-radius: 999px;
      background: #efe5d6;
      border: 1px solid var(--line);
      font-size: 12px;
      letter-spacing: .04em;
      text-transform: uppercase;
    }
    textarea, pre {
      width: 100%;
      min-height: 320px;
      margin: 0;
      border-radius: 14px;
      border: 1px solid var(--line);
      background: #fff;
      color: #15110f;
      padding: 14px;
      font: 13px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      overflow: auto;
      white-space: pre-wrap;
      word-break: break-word;
    }
    button {
      border: 0;
      border-radius: 999px;
      padding: 12px 18px;
      font: inherit;
      cursor: pointer;
      transition: transform .15s ease, opacity .15s ease;
    }
    button:hover { transform: translateY(-1px); }
    button:disabled { opacity: .6; cursor: wait; transform: none; }
    .primary { background: var(--accent); color: #fff; }
    .secondary { background: #efe5d6; color: var(--ink); }
    .danger { background: var(--accent-2); color: #fff; }
    .status {
      min-height: 24px;
      font-size: 14px;
    }
    .ok { color: var(--accent); }
    .err { color: var(--accent-2); }
    @media (min-width: 900px) {
      .grid {
        grid-template-columns: 1.2fr .8fr;
        align-items: start;
      }
    }
  </style>
</head>
<body>
  <main class="shell">
    <section class="hero">
      <div class="row">
        <span class="badge">Mobile Review UI</span>
        <span class="badge">HTTP</span>
        <span class="badge">No JS build step</span>
      </div>
      <h1>Keystone BTC Proof</h1>
      <p>Abra esta página no navegador do celular, ajuste o payload JSON e rode a verificação do bundle em tempo real contra o serviço na VPS.</p>
    </section>

    <section class="grid">
      <article class="panel">
        <div class="row">
          <button id="load" class="secondary">Carregar Exemplo</button>
          <button id="verify" class="primary">Verificar Bundle</button>
          <button id="clear" class="danger">Limpar Resultado</button>
        </div>
        <textarea id="payload" spellcheck="false" placeholder="JSON request"></textarea>
      </article>

      <aside class="panel">
        <div class="row">
          <span class="badge">Resultado</span>
          <span id="status" class="status"></span>
        </div>
        <pre id="result">Carregue um exemplo ou cole um request JSON.</pre>
      </aside>
    </section>
  </main>

  <script>
    const payloadEl = document.getElementById('payload');
    const resultEl = document.getElementById('result');
    const statusEl = document.getElementById('status');
    const verifyBtn = document.getElementById('verify');

    async function loadSample() {
      setStatus('Carregando exemplo...', false);
      const res = await fetch('/api/sample');
      const text = await res.text();
      payloadEl.value = text;
      resultEl.textContent = 'Exemplo carregado.';
      setStatus('Exemplo pronto.', false);
    }

    function setStatus(message, isError) {
      statusEl.textContent = message;
      statusEl.className = 'status ' + (isError ? 'err' : 'ok');
    }

    async function verify() {
      verifyBtn.disabled = true;
      setStatus('Executando verificação...', false);
      try {
        const res = await fetch('/api/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: payloadEl.value
        });
        const text = await res.text();
        resultEl.textContent = text;
        if (res.ok) {
          setStatus('Bundle validado com sucesso.', false);
        } else {
          setStatus('Bundle rejeitado. Veja o JSON de erro.', true);
        }
      } catch (err) {
        resultEl.textContent = String(err);
        setStatus('Falha de rede ou servidor.', true);
      } finally {
        verifyBtn.disabled = false;
      }
    }

    document.getElementById('load').addEventListener('click', loadSample);
    document.getElementById('verify').addEventListener('click', verify);
    document.getElementById('clear').addEventListener('click', () => {
      resultEl.textContent = 'Resultado limpo.';
      setStatus('', false);
    });

    loadSample().catch(err => {
      resultEl.textContent = String(err);
      setStatus('Não foi possível carregar o exemplo.', true);
    });
  </script>
</body>
</html>
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_request_round_trips_into_a_valid_settlement() {
        let request = VerifyRequest::sample().unwrap();
        let input = request.try_into_runtime().unwrap();
        let settlement = evaluate_claim_bundle(
            &input.claim_bundle,
            &input.keys,
            &input.checkpoints,
            &input.l2_context,
        )
        .unwrap();
        assert_eq!(settlement.block_height, 101);
        assert_eq!(settlement.confirmations, 1);
    }

    #[test]
    fn hex_length_validation_is_strict() {
        let err = Hex32("abcd".into()).parse_b256("field").unwrap_err();
        assert!(err.contains("expected 32 bytes"));
    }

    #[test]
    fn index_page_mentions_api_routes() {
        assert!(render_index_html().contains("/api/sample"));
        assert!(render_index_html().contains("/api/verify"));
    }
}
