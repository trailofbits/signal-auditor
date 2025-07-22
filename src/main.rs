mod transparency {
    tonic::include_proto!("transparency");
}
mod kt {
    tonic::include_proto!("kt");
}

use kt::key_transparency_service_client::KeyTransparencyServiceClient;

fn main() {
    let mut client = KeyTransparencyServiceClient::

    let request = tonic::Request::new(kt::AuditRequest {
        start: 0,
        limit: 100,
    });

    let response = client.audit(request).unwrap();
}
