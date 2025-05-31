#[derive(Debug, Clone)]
pub enum Action {
    Execute { command: String },
    Disconnect,
}

#[derive(Debug, Clone)]
pub struct ServerSent {
    _client_id: u32,
    _request_id: u64,
    _action: Action,
}

impl ServerSent {
    pub fn new(client_id: u32, request_id: u64, action: Action) -> Self {
        ServerSent {
            _client_id: client_id,
            _request_id: request_id,
            _action: action,
        }
    }

    pub fn client_id(&self) -> u32 {
        self._client_id
    }

    pub fn request_id(&self) -> u64 {
        self._request_id
    }

    pub fn action(&self) -> &Action {
        &self._action
    }
}

#[derive(Debug, Clone)]
pub struct ClientSent {
    _client_id: u32,
    _request_id: Option<u64>,
    _data: ClientSentData,
}

impl ClientSent {
    pub fn new(client_id: u32, request_id: Option<u64>, data: ClientSentData) -> Self {
        ClientSent {
            _client_id: client_id,
            _request_id: request_id,
            _data: data,
        }
    }

    pub fn client_id(&self) -> u32 {
        self._client_id
    }

    pub fn request_id(&self) -> Option<u64> {
        self._request_id
    }

    pub fn data(&self) -> &ClientSentData {
        &self._data
    }
}

#[derive(Debug, Clone)]
pub enum ClientSentData {
    ClientConnected { version: String },
    ClientDisconnected,
}
