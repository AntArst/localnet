use ggrs::{Message, NonBlockingSocket};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::hash::Hash;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerAddr(pub String);

#[derive(Clone, Default)]
pub struct LocalnetSocket {
    incoming: Arc<Mutex<VecDeque<(PeerAddr, Message)>>>,
    outgoing: Arc<Mutex<VecDeque<(PeerAddr, Message)>>>,
}

impl LocalnetSocket {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enqueue_incoming(&self, addr: PeerAddr, msg: Message) {
        self.incoming
            .lock()
            .expect("incoming queue mutex poisoned")
            .push_back((addr, msg));
    }

    pub fn drain_outgoing(&self) -> Vec<(PeerAddr, Message)> {
        let mut queue = self.outgoing.lock().expect("outgoing queue mutex poisoned");
        queue.drain(..).collect()
    }
}

impl NonBlockingSocket<PeerAddr> for LocalnetSocket {
    fn send_to(&mut self, msg: &Message, addr: &PeerAddr) {
        self.outgoing
            .lock()
            .expect("outgoing queue mutex poisoned")
            .push_back((addr.clone(), msg.clone()));
    }

    fn receive_all_messages(&mut self) -> Vec<(PeerAddr, Message)> {
        let mut queue = self.incoming.lock().expect("incoming queue mutex poisoned");
        queue.drain(..).collect()
    }
}
