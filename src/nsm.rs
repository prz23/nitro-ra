use nsm_io::{Request, Response, AttestationDoc};
use serde_bytes::ByteBuf;

use serde::{Deserialize, Serialize};
use serde_cbor::error::Error as CborError;
use serde_cbor::{from_slice, to_vec};

pub fn get_remote_attestation_document() -> Option<Vec<u8>> {
    let nsm_fd = nsm_driver::nsm_init();

    let public_key = ByteBuf::from("my super secret key");
    let hello = ByteBuf::from("hello, world!");
    let nonce = ByteBuf::from("1");

    let request = Request::Attestation {
        public_key: Some(public_key),
        user_data: Some(hello),
        nonce: Some(nonce),
    };

    let response = nsm_driver::nsm_process_request(nsm_fd, request);

    nsm_driver::nsm_exit(nsm_fd);

    let document = resolve_the_response_doc(response).unwrap();

    Some(document)
}

pub fn resolve_the_response_doc(response:Response) -> Result<Vec<u8>,String> {
    let document = match response {
        Response::Attestation { document } => { document },
        _ => { return Err("the response is not Attestation".to_string()); },
    };

    Ok(document)
}