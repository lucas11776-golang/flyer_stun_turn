use std::sync::{Arc, LazyLock};

use flyer::{Response, Websocket, server, websocket::Socket};
use flyer_event_emitter::{AsyncCallback, Bytes, EventEmitter, Subscription};
use serde::{Serialize, de::DeserializeOwned};
use tokio::sync::RwLock;

static QUEUE: LazyLock<RwLock<Arc<EventEmitter>>> = LazyLock::new(|| RwLock::new(EventEmitter::new()));

pub async fn emit(event: &str, payload: Bytes) {
    QUEUE.read().await.emit(Arc::from(event), payload).await;
}
pub async fn subscribe<C>(event: &str, callback: C) -> Subscription

where
    C: AsyncCallback<Bytes>,
{
    QUEUE.read().await.subscribe(Arc::from(event), callback)
}

pub async fn emit_as<J>(event: &str, payload: &J)
where
    J: Serialize,
{
    QUEUE.read().await.emit_as(Arc::from(event), payload).await;
}

pub async fn subscribe_as<J, C>(event: &str, callback: C) -> Subscription
where
    J: DeserializeOwned + Send + 'static,
    C: AsyncCallback<J>,
{
    QUEUE.read().await.subscribe_as(Arc::from(event), callback)
}

pub fn main() {
    let server = server("127.0.0.1", 8888)
        .view("views");

    server.router().group("/", |router| {
        router.get("1", async |req, res| -> Response {
            res.view("index_01.html", None)
        });

        router.get("2", async |req, res| -> Response {
            res.view("index_02.html", None)
        });
    
        router.ws("{id}", async |req, ws| -> Websocket {
            let socket = ws.socket();
            let client_id = format!("users.{}", req.parameter("id"));
            let client_self = format!("users.{}", req.query("user_id")); // Get in session/jwt

            let _sub = subscribe(&client_self.clone(), move |payload: Bytes| {
                let socket = socket.clone();

                async move {
                    socket.write(payload).await.unwrap();
                }
            }).await;

            ws
                .keep_alive(_sub)
                .text(move |payload: Bytes, socket: Socket| {
                    let event = client_id.clone();

                    async move {
                        emit(&event, payload).await;
                    }

                })
        });
    });

    server.listen();
}
