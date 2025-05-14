// email_sender.rs
use lettre::{
    message::{header::ContentType, Mailbox},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use std::env;
use std::error::Error;
use tracing::{error, info};

pub async fn send_custom_email(
    sender_email: &str,
    receiver_email: &str,
    html: &str,
    subject: &str,
) -> Result<bool, Box<dyn Error>> {
    let mail_server_name = "mail.narsue.com";

    // Determine which password to use
    let password = "testingPassword".to_string();

    // Parse email addresses
    let sender: Mailbox = sender_email.parse()?;
    let receiver: Mailbox = receiver_email.parse()?;

    // Create email message
    let email = Message::builder()
        .from(sender)
        .to(receiver)
        .subject(subject)
        .header(ContentType::TEXT_HTML)
        .body(html.to_string())?;

    // Second attempt - TLS on port 465 (common secure alternative)
    info!("Attempting SMTP connection using TLS on port 465");
    let creds = Credentials::new(sender_email.to_string(), password.clone());
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(mail_server_name)?
        .credentials(creds)
        .port(465)
        .build();

    match mailer.send(email.clone()).await {
        Ok(_) => {
            info!("Email sent successfully using TLS on port 465");
            return Ok(true);
        }
        Err(e) => {
            error!("Failed with TLS on port 465: {}", e);
            Ok(false)
            // Continue to last attempt
        }
    }

}
