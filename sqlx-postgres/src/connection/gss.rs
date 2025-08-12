
use crate::error::Error;
use crate::message::Authentication;
use crate::{connection::PgStream, message::{AuthenticationGss, GssResponse}, PgConnectOptions};

use cross_krb5::{ClientCtx, InitiateFlags, Step};

/// Authenticate using GSSAPI (Kerberos).
pub(crate) async fn authenticate(
    stream: &mut PgStream,
    options: &PgConnectOptions,
    data: AuthenticationGss,
) -> Result<(), Error> {
    // The frontend must now initiate a GSSAPI negotiation.
    let spn = format!("postgres/{}", options.host);
    let (mut client, token) = ClientCtx::new(
        InitiateFlags::empty(), None, &spn, Some(&data.body())
    ).expect("new");

    // The frontend will send a GSSResponse message with the first part of the GSSAPI 
    // data stream in response to this.
    stream.send(GssResponse(&*token)).await?;

    loop {
        match stream.recv_expect().await? {
            // If further messages are needed, the server will respond with AuthenticationGSSContinue.
            Authentication::GssContinue(data) => {
                let mut token = data.body();
                // Process the GSSAPI token.
                match client.step(&mut token).expect("step") {
                    Step::Finished((_, token)) => {
                        // Authentication is complete.
                        if let Some(token) = token {
                            // Send the final GSS response.
                            stream.send(GssResponse(&*token)).await?;
                        }
                        break;
                    }
                    Step::Continue((ctx, token)) => {
                        // Continue the GSSAPI negotiation.
                        // Send the next GSS response.
                        stream.send(GssResponse(&*token)).await?;
                        client = ctx;
                    }
                }
            },
            Authentication::Ok => break,
            // If the server sends an error, we return it.
            auth => return Err(err_protocol!("Expected Authentication but received {:?}", auth)),
        };
    };

    Ok(())
}
