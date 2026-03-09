#![allow(dead_code)]

wit_bindgen::generate!({
    world: "sandboxed-channel",
    path: "wit/channel.wit",
});

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use exports::near::agent::channel::{
    AgentResponse, ChannelConfig, Guest, HttpEndpointConfig, IncomingHttpRequest,
    OutgoingHttpResponse, StatusType, StatusUpdate,
};
use near::agent::channel_host::{self, EmittedMessage, InboundAttachment};

const CHANNEL_NAME: &str = "qqbot";
const DEFAULT_WEBHOOK_PATH: &str = "/webhook/qqbot";
const DEFAULT_API_BASE: &str = "https://api.sgroup.qq.com";
const DEFAULT_TOKEN_URL: &str = "https://bots.qq.com/app/getAppAccessToken";

const CONFIG_PATH: &str = "state/config.json";
const TOKEN_CACHE_PATH: &str = "state/access_token.json";

const OP_DISPATCH_EVENT: u32 = 0;
const OP_HEARTBEAT: u32 = 1;
const OP_HEARTBEAT_ACK: u32 = 11;
const OP_HTTP_CALLBACK_ACK: u32 = 12;
const OP_HTTP_CALLBACK_VALIDATION: u32 = 13;

const SIG_HEADER: &str = "x-signature-ed25519";
const TS_HEADER: &str = "x-signature-timestamp";

#[derive(Debug, Clone, Deserialize, Serialize)]
struct QQBotConfig {
    #[serde(default)]
    app_id: String,
    #[serde(default)]
    app_secret: String,
    #[serde(default = "default_api_base")]
    api_base: String,
    #[serde(default = "default_token_url")]
    token_url: String,
    #[serde(default = "default_webhook_path")]
    webhook_path: String,
    #[serde(default = "default_reply_to_message")]
    reply_to_message: bool,
    #[serde(default = "default_verify_signature")]
    verify_signature: bool,
    #[serde(default)]
    markdown_support: bool,
    #[serde(default = "default_enable_input_notify")]
    enable_input_notify: bool,
    #[serde(default = "default_input_notify_seconds")]
    input_notify_seconds: u32,
    #[serde(default)]
    owner_id: Option<String>,
    #[serde(default)]
    dm_policy: Option<String>,
    #[serde(default)]
    allow_from: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CallbackPayload {
    op: u32,
    #[serde(default)]
    d: Value,
    #[serde(default)]
    s: Option<u32>,
    #[serde(default)]
    t: Option<String>,
    #[serde(default)]
    id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ValidationPayload {
    plain_token: String,
    event_ts: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedToken {
    access_token: String,
    expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResponseMetadata {
    route: RouteKind,
    target_id: String,
    sender_id: String,
    sender_name: Option<String>,
    reply_to_message_id: Option<String>,
    guild_id: Option<String>,
    channel_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RouteKind {
    C2c,
    Group,
    Guild,
    DirectMessage,
}

#[derive(Debug, Deserialize)]
struct QqAttachment {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    filename: Option<String>,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    width: Option<u32>,
    #[serde(default)]
    height: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct QqC2cAuthor {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    user_openid: String,
    #[serde(default)]
    union_openid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct QqC2cMessage {
    id: String,
    #[serde(default)]
    content: String,
    timestamp: String,
    author: QqC2cAuthor,
    #[serde(default)]
    attachments: Vec<QqAttachment>,
}

#[derive(Debug, Deserialize)]
struct QqGroupAuthor {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    member_openid: String,
}

#[derive(Debug, Deserialize)]
struct QqGroupMessage {
    id: String,
    #[serde(default)]
    content: String,
    timestamp: String,
    #[serde(default)]
    group_id: Option<String>,
    #[serde(default)]
    group_openid: String,
    author: QqGroupAuthor,
    #[serde(default)]
    attachments: Vec<QqAttachment>,
}

#[derive(Debug, Deserialize)]
struct QqGuildAuthor {
    #[serde(default)]
    id: String,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    bot: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct QqGuildMessage {
    id: String,
    #[serde(default)]
    channel_id: Option<String>,
    #[serde(default)]
    guild_id: Option<String>,
    #[serde(default)]
    content: String,
    timestamp: String,
    author: QqGuildAuthor,
    #[serde(default)]
    attachments: Vec<QqAttachment>,
}

#[derive(Debug, Clone, Copy)]
enum IncomingScene {
    C2c,
    Group,
    Guild,
    DirectMessage,
}

#[derive(Debug)]
struct InboundEnvelope {
    scene: IncomingScene,
    sender_id: String,
    sender_name: Option<String>,
    message_id: String,
    content: String,
    target_id: String,
    guild_id: Option<String>,
    channel_id: Option<String>,
    attachments: Vec<InboundAttachment>,
}

#[derive(Debug)]
struct SendTarget {
    route: RouteKind,
    id: String,
}

fn default_api_base() -> String {
    DEFAULT_API_BASE.to_string()
}

fn default_token_url() -> String {
    DEFAULT_TOKEN_URL.to_string()
}

fn default_webhook_path() -> String {
    DEFAULT_WEBHOOK_PATH.to_string()
}

fn default_reply_to_message() -> bool {
    true
}

fn default_verify_signature() -> bool {
    true
}

fn default_enable_input_notify() -> bool {
    true
}

fn default_input_notify_seconds() -> u32 {
    60
}

struct QQBotChannel;

impl Guest for QQBotChannel {
    fn on_start(config_json: String) -> Result<ChannelConfig, String> {
        let config = parse_config(&config_json);
        persist_config(&config)?;

        channel_host::log(
            channel_host::LogLevel::Info,
            &format!(
                "QQBot channel starting (path: {}, configured_app_id: {}, verify_signature: {})",
                config.webhook_path,
                !config.app_id.is_empty(),
                config.verify_signature,
            ),
        );

        if config.app_id.is_empty() || config.app_secret.is_empty() {
            channel_host::log(
                channel_host::LogLevel::Warn,
                "qqbot config is missing app_id/app_secret; webhook validation and replies will fail until config is updated",
            );
        }

        Ok(ChannelConfig {
            display_name: "QQ Bot".to_string(),
            http_endpoints: vec![HttpEndpointConfig {
                path: config.webhook_path,
                methods: vec!["POST".to_string()],
                require_secret: false,
            }],
            poll: None,
        })
    }

    fn on_http_request(req: IncomingHttpRequest) -> OutgoingHttpResponse {
        if req.method != "POST" {
            return json_response(405, json!({ "error": "method_not_allowed" }));
        }

        let config = load_config();
        let headers = parse_json_map(&req.headers_json);

        if config.verify_signature {
            match verify_incoming_signature(&config, &headers, &req.body) {
                Ok(true) => {}
                Ok(false) => {
                    channel_host::log(
                        channel_host::LogLevel::Warn,
                        "qqbot webhook signature verification failed",
                    );
                    return json_response(401, json!({ "error": "invalid_signature" }));
                }
                Err(err) => {
                    channel_host::log(
                        channel_host::LogLevel::Error,
                        &format!("qqbot signature verification error: {err}"),
                    );
                    return json_response(401, json!({ "error": "signature_error", "details": err }));
                }
            }
        }

        let payload: CallbackPayload = match serde_json::from_slice(&req.body) {
            Ok(payload) => payload,
            Err(err) => {
                channel_host::log(
                    channel_host::LogLevel::Error,
                    &format!("failed to parse qqbot callback payload: {err}"),
                );
                return dispatch_ack(false);
            }
        };

        match payload.op {
            OP_HTTP_CALLBACK_VALIDATION => match handle_validation_request(&config, &payload.d) {
                Ok(body) => OutgoingHttpResponse {
                    status: 200,
                    headers_json: json!({ "Content-Type": "application/json" }).to_string(),
                    body,
                },
                Err(err) => json_response(500, json!({ "error": "validation_failed", "details": err })),
            },
            OP_HEARTBEAT => heartbeat_ack(payload.d.as_u64().unwrap_or_default() as u32),
            OP_DISPATCH_EVENT => {
                let ok = handle_dispatch_event(&config, &payload);
                dispatch_ack(ok)
            }
            other => {
                channel_host::log(
                    channel_host::LogLevel::Debug,
                    &format!("ignoring unsupported qqbot callback op={other}"),
                );
                json_response(200, json!({ "status": "ignored", "op": other }))
            }
        }
    }

    fn on_poll() {}

    fn on_respond(response: AgentResponse) -> Result<(), String> {
        let config = load_config();
        let metadata: ResponseMetadata = serde_json::from_str(&response.metadata_json)
            .map_err(|err| format!("failed to parse response metadata: {err}"))?;

        send_agent_response(&config, &metadata, &response.content)
    }

    fn on_status(update: StatusUpdate) {
        if !matches!(update.status, StatusType::Thinking) {
            return;
        }

        let config = load_config();
        if !config.enable_input_notify {
            return;
        }

        let metadata: ResponseMetadata = match serde_json::from_str(&update.metadata_json) {
            Ok(value) => value,
            Err(_) => return,
        };

        if metadata.route != RouteKind::C2c {
            return;
        }

        let msg_id = metadata.reply_to_message_id.as_deref();
        if let Err(err) = send_input_notify(&config, &metadata.sender_id, msg_id) {
            channel_host::log(
                channel_host::LogLevel::Warn,
                &format!("failed to send qqbot input_notify: {err}"),
            );
        }
    }

    fn on_broadcast(user_id: String, response: AgentResponse) -> Result<(), String> {
        let config = load_config();
        let target = parse_send_target(&user_id);
        send_text_message(&config, &target, &response.content, None)
    }

    fn on_shutdown() {
        channel_host::log(channel_host::LogLevel::Info, "QQBot channel shutting down");
    }
}

fn parse_config(config_json: &str) -> QQBotConfig {
    match serde_json::from_str::<QQBotConfig>(config_json) {
        Ok(mut config) => {
            if config.dm_policy.is_none() {
                config.dm_policy = Some("pairing".to_string());
            }
            config
        }
        Err(err) => {
            channel_host::log(
                channel_host::LogLevel::Warn,
                &format!("failed to parse qqbot config, using defaults: {err}"),
            );
            QQBotConfig {
                app_id: String::new(),
                app_secret: String::new(),
                api_base: default_api_base(),
                token_url: default_token_url(),
                webhook_path: default_webhook_path(),
                reply_to_message: default_reply_to_message(),
                verify_signature: default_verify_signature(),
                markdown_support: false,
                enable_input_notify: default_enable_input_notify(),
                input_notify_seconds: default_input_notify_seconds(),
                owner_id: None,
                dm_policy: Some("pairing".to_string()),
                allow_from: Vec::new(),
            }
        }
    }
}

fn persist_config(config: &QQBotConfig) -> Result<(), String> {
    let payload = serde_json::to_string(config).map_err(|err| err.to_string())?;
    channel_host::workspace_write(CONFIG_PATH, &payload).map_err(|err| err.to_string())
}

fn load_config() -> QQBotConfig {
    channel_host::workspace_read(CONFIG_PATH)
        .and_then(|raw| serde_json::from_str::<QQBotConfig>(&raw).ok())
        .unwrap_or_else(|| parse_config("{}"))
}

fn parse_json_map(raw: &str) -> serde_json::Map<String, Value> {
    serde_json::from_str::<Value>(raw)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default()
}

fn get_header<'a>(headers: &'a serde_json::Map<String, Value>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .and_then(|(_, value)| value.as_str())
}

fn verify_incoming_signature(
    config: &QQBotConfig,
    headers: &serde_json::Map<String, Value>,
    body: &[u8],
) -> Result<bool, String> {
    if config.app_secret.is_empty() {
        return Err("app_secret is empty".to_string());
    }

    let sig_hex = get_header(headers, SIG_HEADER)
        .ok_or_else(|| "missing x-signature-ed25519 header".to_string())?;
    let timestamp = get_header(headers, TS_HEADER)
        .ok_or_else(|| "missing x-signature-timestamp header".to_string())?;

    let signature_bytes = hex::decode(sig_hex).map_err(|err| format!("invalid signature hex: {err}"))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|err| format!("invalid signature bytes: {err}"))?;

    let verifying_key = derive_verifying_key(&config.app_secret)?;
    let message = build_signature_message(timestamp, body);
    Ok(verifying_key.verify(&message, &signature).is_ok())
}

fn handle_validation_request(config: &QQBotConfig, data: &Value) -> Result<Vec<u8>, String> {
    if config.app_secret.is_empty() {
        return Err("app_secret is required for webhook validation".to_string());
    }

    let validation: ValidationPayload = serde_json::from_value(data.clone())
        .map_err(|err| format!("invalid validation payload: {err}"))?;

    let signing_key = derive_signing_key(&config.app_secret)?;
    let signature_message = build_signature_message(&validation.event_ts, validation.plain_token.as_bytes());
    let signature = signing_key.sign(&signature_message);

    serde_json::to_vec(&json!({
        "plain_token": validation.plain_token,
        "signature": hex::encode(signature.to_bytes()),
    }))
    .map_err(|err| err.to_string())
}

fn handle_dispatch_event(config: &QQBotConfig, payload: &CallbackPayload) -> bool {
    let Some(event_type) = payload.t.as_deref() else {
        channel_host::log(channel_host::LogLevel::Warn, "dispatch payload missing event type");
        return false;
    };

    let envelope = match build_inbound_envelope(event_type, &payload.d) {
        Ok(Some(envelope)) => envelope,
        Ok(None) => return true,
        Err(err) => {
            channel_host::log(
                channel_host::LogLevel::Error,
                &format!("failed to parse qqbot event {event_type}: {err}"),
            );
            return false;
        }
    };

    if !sender_allowed(config, &envelope) {
        maybe_handle_pairing(config, &envelope);
        return true;
    }

    let metadata = ResponseMetadata {
        route: route_for_scene(envelope.scene),
        target_id: envelope.target_id.clone(),
        sender_id: envelope.sender_id.clone(),
        sender_name: envelope.sender_name.clone(),
        reply_to_message_id: Some(envelope.message_id.clone()),
        guild_id: envelope.guild_id.clone(),
        channel_id: envelope.channel_id.clone(),
    };

    let metadata_json = serde_json::to_string(&metadata).unwrap_or_else(|_| "{}".to_string());

    channel_host::emit_message(&EmittedMessage {
        user_id: envelope.sender_id,
        user_name: envelope.sender_name,
        content: envelope.content,
        thread_id: None,
        metadata_json,
        attachments: envelope.attachments,
    });

    true
}

fn build_inbound_envelope(event_type: &str, data: &Value) -> Result<Option<InboundEnvelope>, String> {
    match event_type {
        "C2C_MESSAGE_CREATE" => {
            let event: QqC2cMessage = serde_json::from_value(data.clone()).map_err(|err| err.to_string())?;
            let sender_id = if event.author.user_openid.is_empty() {
                event.author.id.unwrap_or_default()
            } else {
                event.author.user_openid
            };
            Ok(Some(InboundEnvelope {
                scene: IncomingScene::C2c,
                sender_id: sender_id.clone(),
                sender_name: None,
                message_id: event.id.clone(),
                content: content_for_emit(&event.content, IncomingScene::C2c, !event.attachments.is_empty()),
                target_id: sender_id,
                guild_id: None,
                channel_id: None,
                attachments: convert_attachments("c2c", &event.id, event.attachments),
            }))
        }
        "GROUP_AT_MESSAGE_CREATE" => {
            let event: QqGroupMessage = serde_json::from_value(data.clone()).map_err(|err| err.to_string())?;
            let target_id = if event.group_openid.is_empty() {
                event.group_id.unwrap_or_default()
            } else {
                event.group_openid
            };
            Ok(Some(InboundEnvelope {
                scene: IncomingScene::Group,
                sender_id: event.author.member_openid,
                sender_name: None,
                message_id: event.id.clone(),
                content: content_for_emit(&event.content, IncomingScene::Group, !event.attachments.is_empty()),
                target_id,
                guild_id: None,
                channel_id: None,
                attachments: convert_attachments("group", &event.id, event.attachments),
            }))
        }
        "AT_MESSAGE_CREATE" => {
            let event: QqGuildMessage = serde_json::from_value(data.clone()).map_err(|err| err.to_string())?;
            Ok(build_guild_like_envelope(event, IncomingScene::Guild))
        }
        "DIRECT_MESSAGE_CREATE" => {
            let event: QqGuildMessage = serde_json::from_value(data.clone()).map_err(|err| err.to_string())?;
            Ok(build_guild_like_envelope(event, IncomingScene::DirectMessage))
        }
        _ => {
            channel_host::log(
                channel_host::LogLevel::Debug,
                &format!("ignoring qqbot event {event_type}"),
            );
            Ok(None)
        }
    }
}

fn build_guild_like_envelope(event: QqGuildMessage, scene: IncomingScene) -> Option<InboundEnvelope> {
    let sender_id = event.author.id;
    let target_id = match scene {
        IncomingScene::Guild => event.channel_id.clone().unwrap_or_default(),
        IncomingScene::DirectMessage => event.guild_id.clone().unwrap_or_default(),
        _ => String::new(),
    };
    if sender_id.is_empty() || target_id.is_empty() {
        return None;
    }

    Some(InboundEnvelope {
        scene,
        sender_id,
        sender_name: event.author.username,
        message_id: event.id.clone(),
        content: content_for_emit(&event.content, scene, !event.attachments.is_empty()),
        target_id,
        guild_id: event.guild_id,
        channel_id: event.channel_id,
        attachments: convert_attachments(
            if matches!(scene, IncomingScene::Guild) { "guild" } else { "dm" },
            &event.id,
            event.attachments,
        ),
    })
}

fn route_for_scene(scene: IncomingScene) -> RouteKind {
    match scene {
        IncomingScene::C2c => RouteKind::C2c,
        IncomingScene::Group => RouteKind::Group,
        IncomingScene::Guild => RouteKind::Guild,
        IncomingScene::DirectMessage => RouteKind::DirectMessage,
    }
}

fn content_for_emit(content: &str, scene: IncomingScene, has_attachments: bool) -> String {
    let cleaned = match scene {
        IncomingScene::Group | IncomingScene::Guild => clean_qq_mentions(content),
        _ => clean_spaces(content),
    };

    if cleaned.is_empty() && has_attachments {
        String::new()
    } else {
        cleaned
    }
}

fn clean_qq_mentions(content: &str) -> String {
    let mention_re = Regex::new(r"<@!?\d+>").unwrap();
    clean_spaces(&mention_re.replace_all(content, ""))
}

fn clean_spaces(content: &str) -> String {
    content.trim_matches(|ch| ch == ' ' || ch == '\u{00A0}' || ch == '\n' || ch == '\t' || ch == '\r').to_string()
}

fn convert_attachments(prefix: &str, message_id: &str, attachments: Vec<QqAttachment>) -> Vec<InboundAttachment> {
    attachments
        .into_iter()
        .enumerate()
        .map(|(index, attachment)| {
            let mut extras = serde_json::Map::new();
            if let Some(width) = attachment.width {
                extras.insert("width".to_string(), json!(width));
            }
            if let Some(height) = attachment.height {
                extras.insert("height".to_string(), json!(height));
            }
            InboundAttachment {
                id: format!("{prefix}:{message_id}:{index}"),
                mime_type: attachment
                    .content_type
                    .unwrap_or_else(|| "application/octet-stream".to_string()),
                filename: attachment.filename,
                size_bytes: attachment.size,
                source_url: attachment.url.and_then(|url| normalize_attachment_url(&url)),
                storage_key: None,
                extracted_text: None,
                extras_json: Value::Object(extras).to_string(),
            }
        })
        .collect()
}

fn normalize_attachment_url(url: &str) -> Option<String> {
    if url.is_empty() {
        return None;
    }
    if url.starts_with("http://") || url.starts_with("https://") {
        return Some(url.to_string());
    }
    if url.starts_with("//") {
        return Some(format!("https:{url}"));
    }
    Some(format!("https://{url}"))
}

fn sender_allowed(config: &QQBotConfig, envelope: &InboundEnvelope) -> bool {
    if let Some(owner_id) = config.owner_id.as_deref() {
        return envelope.sender_id == owner_id
            || envelope.sender_name.as_deref() == Some(owner_id);
    }

    if matches_allow_from(&config.allow_from, &envelope.sender_id, envelope.sender_name.as_deref()) {
        return true;
    }

    match envelope.scene {
        IncomingScene::C2c | IncomingScene::DirectMessage => matches!(config.dm_policy.as_deref(), Some("open")),
        IncomingScene::Group | IncomingScene::Guild => config.allow_from.is_empty(),
    }
}

fn matches_allow_from(allow_from: &[String], sender_id: &str, sender_name: Option<&str>) -> bool {
    if allow_from.is_empty() {
        return false;
    }

    allow_from.iter().any(|entry| {
        entry == "*"
            || entry.eq_ignore_ascii_case(sender_id)
            || sender_name.is_some_and(|name| entry.eq_ignore_ascii_case(name))
    })
}

fn maybe_handle_pairing(config: &QQBotConfig, envelope: &InboundEnvelope) {
    if !matches!(envelope.scene, IncomingScene::C2c | IncomingScene::DirectMessage) {
        return;
    }
    if !matches!(config.dm_policy.as_deref(), Some("pairing")) {
        return;
    }

    let meta = json!({
        "sender_id": envelope.sender_id,
        "sender_name": envelope.sender_name,
        "scene": match envelope.scene {
            IncomingScene::C2c => "c2c",
            IncomingScene::DirectMessage => "direct_message",
            _ => "other",
        }
    })
    .to_string();

    match channel_host::pairing_upsert_request(CHANNEL_NAME, &envelope.sender_id, &meta) {
        Ok(result) => {
            if result.created {
                let content = format!(
                    "To pair with this bot, run: ironclaw pairing approve qqbot {}",
                    result.code
                );
                let target = SendTarget {
                    route: route_for_scene(envelope.scene),
                    id: envelope.target_id.clone(),
                };
                let _ = send_text_message(config, &target, &content, None);
            }
        }
        Err(err) => channel_host::log(
            channel_host::LogLevel::Warn,
            &format!("qqbot pairing request failed: {err}"),
        ),
    }
}

fn send_agent_response(config: &QQBotConfig, metadata: &ResponseMetadata, content: &str) -> Result<(), String> {
    let target = SendTarget {
        route: metadata.route,
        id: metadata.target_id.clone(),
    };
    let reply_to = if config.reply_to_message {
        metadata.reply_to_message_id.as_deref()
    } else {
        None
    };
    send_text_message(config, &target, content, reply_to)
}

fn send_input_notify(config: &QQBotConfig, openid: &str, msg_id: Option<&str>) -> Result<(), String> {
    let access_token = get_access_token(config)?;
    let mut body = json!({
        "msg_type": 6,
        "input_notify": {
            "input_type": 1,
            "input_second": config.input_notify_seconds,
        },
        "msg_seq": next_msg_seq(),
    });
    if let Some(msg_id) = msg_id {
        body["msg_id"] = Value::String(msg_id.to_string());
    }

    qq_api_request(
        config,
        "POST",
        &format!("{}/v2/users/{openid}/messages", config.api_base),
        Some(body),
        &access_token,
    )
    .map(|_| ())
}

fn send_text_message(
    config: &QQBotConfig,
    target: &SendTarget,
    content: &str,
    reply_to_message_id: Option<&str>,
) -> Result<(), String> {
    let access_token = get_access_token(config)?;
    let body = match target.route {
        RouteKind::C2c | RouteKind::Group => build_reply_body(content, reply_to_message_id),
        RouteKind::Guild | RouteKind::DirectMessage => build_simple_body(content, reply_to_message_id),
    };

    let url = match target.route {
        RouteKind::C2c => format!("{}/v2/users/{}/messages", config.api_base, target.id),
        RouteKind::Group => format!("{}/v2/groups/{}/messages", config.api_base, target.id),
        RouteKind::Guild => format!("{}/channels/{}/messages", config.api_base, target.id),
        RouteKind::DirectMessage => format!("{}/dms/{}/messages", config.api_base, target.id),
    };

    qq_api_request(config, "POST", &url, Some(body), &access_token).map(|_| ())
}

fn build_reply_body(content: &str, msg_id: Option<&str>) -> Value {
    let mut body = json!({
        "content": content,
        "msg_type": 0,
        "msg_seq": next_msg_seq(),
    });
    if let Some(msg_id) = msg_id {
        body["msg_id"] = Value::String(msg_id.to_string());
    }
    body
}

fn build_simple_body(content: &str, msg_id: Option<&str>) -> Value {
    let mut body = json!({
        "content": content,
    });
    if let Some(msg_id) = msg_id {
        body["msg_id"] = Value::String(msg_id.to_string());
    }
    body
}

fn qq_api_request(
    _config: &QQBotConfig,
    method: &str,
    url: &str,
    body: Option<Value>,
    access_token: &str,
) -> Result<Value, String> {
    let headers = json!({
        "Content-Type": "application/json",
        "Authorization": format!("QQBot {access_token}"),
    });
    let body_bytes = match body {
        Some(value) => Some(serde_json::to_vec(&value).map_err(|err| err.to_string())?),
        None => None,
    };

    let response = channel_host::http_request(method, url, &headers.to_string(), body_bytes.as_deref(), None)
        .map_err(|err| format!("http request failed: {err}"))?;

    let response_json: Value = serde_json::from_slice(&response.body)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&response.body) }));

    if response.status < 200 || response.status >= 300 {
        return Err(format!(
            "qqbot api {} {} failed with status {}: {}",
            method,
            url,
            response.status,
            response_json
        ));
    }

    Ok(response_json)
}

fn get_access_token(config: &QQBotConfig) -> Result<String, String> {
    if config.app_id.is_empty() || config.app_secret.is_empty() {
        return Err("qqbot app_id/app_secret are required".to_string());
    }

    if let Some(raw) = channel_host::workspace_read(TOKEN_CACHE_PATH) {
        if let Ok(cache) = serde_json::from_str::<CachedToken>(&raw) {
            if channel_host::now_millis() + 60_000 < cache.expires_at_ms {
                return Ok(cache.access_token);
            }
        }
    }

    let token_req = json!({
        "appId": config.app_id,
        "clientSecret": config.app_secret,
    });
    let headers = json!({ "Content-Type": "application/json" });
    let body_bytes = serde_json::to_vec(&token_req).map_err(|err| err.to_string())?;
    let response = channel_host::http_request(
        "POST",
        &config.token_url,
        &headers.to_string(),
        Some(&body_bytes),
        None,
    )
    .map_err(|err| format!("qqbot token request failed: {err}"))?;

    let token_response: TokenResponse = serde_json::from_slice(&response.body)
        .map_err(|err| format!("failed to parse qqbot token response: {err}"))?;

    if response.status < 200 || response.status >= 300 || token_response.access_token.is_empty() {
        return Err(format!(
            "qqbot token request returned status {} code {} message {}",
            response.status,
            token_response.code,
            token_response.message.unwrap_or_default()
        ));
    }

    let expires_in = token_response.expires_in.max(120);
    let cache = CachedToken {
        access_token: token_response.access_token,
        expires_at_ms: channel_host::now_millis() + expires_in * 1000,
    };

    if let Ok(serialized) = serde_json::to_string(&cache) {
        let _ = channel_host::workspace_write(TOKEN_CACHE_PATH, &serialized);
    }

    Ok(cache.access_token)
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    access_token: String,
    #[serde(default, deserialize_with = "deserialize_u64ish")]
    expires_in: u64,
}

fn deserialize_u64ish<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    match value {
        Value::Number(number) => number
            .as_u64()
            .ok_or_else(|| serde::de::Error::custom("expires_in must be a positive integer")),
        Value::String(text) => text
            .parse::<u64>()
            .map_err(|err| serde::de::Error::custom(err.to_string())),
        Value::Null => Ok(0),
        other => Err(serde::de::Error::custom(format!("unsupported expires_in value: {other}"))),
    }
}

fn next_msg_seq() -> u32 {
    ((channel_host::now_millis() % 65535) as u32).max(1)
}

fn parse_send_target(user_id: &str) -> SendTarget {
    if let Some(rest) = user_id.strip_prefix("group:") {
        return SendTarget {
            route: RouteKind::Group,
            id: rest.to_string(),
        };
    }
    if let Some(rest) = user_id.strip_prefix("channel:") {
        return SendTarget {
            route: RouteKind::Guild,
            id: rest.to_string(),
        };
    }
    if let Some(rest) = user_id.strip_prefix("dm:") {
        return SendTarget {
            route: RouteKind::DirectMessage,
            id: rest.to_string(),
        };
    }
    if let Some(rest) = user_id.strip_prefix("c2c:") {
        return SendTarget {
            route: RouteKind::C2c,
            id: rest.to_string(),
        };
    }
    SendTarget {
        route: RouteKind::C2c,
        id: user_id.to_string(),
    }
}

fn derive_signing_key(secret: &str) -> Result<SigningKey, String> {
    let seed = derive_secret_seed(secret)?;
    Ok(SigningKey::from_bytes(&seed))
}

fn derive_verifying_key(secret: &str) -> Result<VerifyingKey, String> {
    Ok(derive_signing_key(secret)?.verifying_key())
}

fn derive_secret_seed(secret: &str) -> Result<[u8; 32], String> {
    if secret.is_empty() {
        return Err("secret is empty".to_string());
    }

    let mut expanded = secret.as_bytes().to_vec();
    while expanded.len() < 32 {
        expanded.extend_from_within(..);
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&expanded[..32]);
    Ok(seed)
}

fn build_signature_message(timestamp: &str, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(timestamp.len() + body.len());
    message.extend_from_slice(timestamp.as_bytes());
    message.extend_from_slice(body);
    message
}

fn heartbeat_ack(seq: u32) -> OutgoingHttpResponse {
    json_response(200, json!({ "op": OP_HEARTBEAT_ACK, "d": seq }))
}

fn dispatch_ack(success: bool) -> OutgoingHttpResponse {
    json_response(
        200,
        json!({ "op": OP_HTTP_CALLBACK_ACK, "d": if success { 0 } else { 1 } }),
    )
}

fn json_response(status: u16, value: Value) -> OutgoingHttpResponse {
    OutgoingHttpResponse {
        status,
        headers_json: json!({ "Content-Type": "application/json" }).to_string(),
        body: serde_json::to_vec(&value).unwrap_or_default(),
    }
}

export!(QQBotChannel);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_mentions() {
        assert_eq!(clean_qq_mentions("<@!12345>  hello  "), "hello");
        assert_eq!(clean_qq_mentions("<@12345>\u{00A0}world"), "world");
    }

    #[test]
    fn test_parse_send_target() {
        assert!(matches!(parse_send_target("group:abc").route, RouteKind::Group));
        assert!(matches!(parse_send_target("channel:abc").route, RouteKind::Guild));
        assert!(matches!(parse_send_target("dm:abc").route, RouteKind::DirectMessage));
        assert!(matches!(parse_send_target("plain-openid").route, RouteKind::C2c));
    }

    #[test]
    fn test_derive_secret_seed_repeats() {
        let seed = derive_secret_seed("abc").unwrap();
        assert_eq!(&seed[..6], b"abcabc");
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn test_build_signature_message() {
        let msg = build_signature_message("123", b"payload");
        assert_eq!(msg, b"123payload");
    }

    #[test]
    fn test_normalize_attachment_url() {
        assert_eq!(normalize_attachment_url("//cdn.example.com/a.png").unwrap(), "https://cdn.example.com/a.png");
        assert_eq!(normalize_attachment_url("cdn.example.com/a.png").unwrap(), "https://cdn.example.com/a.png");
    }
}
