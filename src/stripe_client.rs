use std::collections::HashMap;

use actix_web::dev;
// Add these methods to your StripeClient impl block
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct SetupIntent {
    pub id: String,
    pub client_secret: String,
    pub status: String,
    pub payment_method: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Customer {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaymentMethod {
    pub id: String,
    pub r#type: String,
    pub card: Option<CardDetails>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CardDetails {
    pub brand: String,
    pub last4: String,
    pub exp_month: i32,
    pub exp_year: i32,
}

// Add the StripeClient struct definition
pub struct StripeClient {
    pub client: reqwest::Client,
    pub base_url: String,
    pub public_key: String,
    pub secret_key: String,
    pub dev_mode: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct StripeConfig {
    dev_secret_key: Option<String>,
    dev_public_key: Option<String>,
    prod_secret_key: Option<String>,
    prod_public_key: Option<String>,
}

impl StripeClient {
pub fn new(dev_mode: bool) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let config = Self::load_config()?;
        if dev_mode {
            if let (Some(secret_key), Some(public_key)) = (config.dev_secret_key, config.dev_public_key) {
                return Ok(Self {
                    client: reqwest::Client::new(),
                    secret_key,
                    public_key,
                    base_url: "https://api.stripe.com/v1".to_string(),
                    dev_mode
                });
            } else {
                return Err("Development keys not found in config".into());
            }
        }

        // For production mode, use the production keys
        if config.prod_secret_key.is_none() || config.prod_public_key.is_none() {
            return Err("Production keys not found in config".into());
        }

        // Create the StripeClient with production keys
        Ok(Self {
            client: reqwest::Client::new(),
            secret_key: config.prod_secret_key.unwrap(),
            public_key: config.prod_public_key.unwrap(),
            base_url: "https://api.stripe.com/v1".to_string(),
            dev_mode
        })


    }

    pub fn with_keys(secret_key: String, public_key: String, dev_mode: bool) -> Self {
        Self {
            client: reqwest::Client::new(),
            secret_key,
            public_key,
            base_url: "https://api.stripe.com/v1".to_string(),
            dev_mode
        }
    }

    fn load_config() -> Result<StripeConfig, Box<dyn std::error::Error + Send + Sync>> {
        let config_path = Path::new("auth/stripe.json");
        
        if !config_path.exists() {
            return Err("auth/stripe.json file not found".into());
        }

        let config_content = fs::read_to_string(config_path)?;
        let config: StripeConfig = serde_json::from_str(&config_content)?;
        
        Ok(config)
    }

    pub async fn create_customer(
        &self,
        email: &str,
        name: Option<&str>,
    ) -> Result<Customer, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/customers", self.base_url);
        
        let mut form_data = HashMap::new();
        form_data.insert("email".to_string(), email.to_string());
        
        if let Some(customer_name) = name {
            form_data.insert("name".to_string(), customer_name.to_string());
        }

        let response = self
            .client
            .post(&url)
            .basic_auth(&self.secret_key, Some(""))
            .form(&form_data)
            .send()
            .await?;

        if response.status().is_success() {
            let customer: Customer = response.json().await?;
            Ok(customer)
        } else {
            let error_text = response.text().await?;
            Err(format!("Stripe API Error: {}", error_text).into())
        }
    }

    pub async fn create_setup_intent(
        &self,
        customer_id: &str,
    ) -> Result<SetupIntent, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/setup_intents", self.base_url);
        
        let mut form_data = HashMap::new();
        form_data.insert("customer".to_string(), customer_id.to_string());
        form_data.insert("usage".to_string(), "off_session".to_string());

        let response = self
            .client
            .post(&url)
            .basic_auth(&self.secret_key, Some(""))
            .form(&form_data)
            .send()
            .await?;

        if response.status().is_success() {
            let setup_intent: SetupIntent = response.json().await?;
            Ok(setup_intent)
        } else {
            let error_text = response.text().await?;
            Err(format!("Stripe API Error: {}", error_text).into())
        }
    }

    pub async fn list_payment_methods(
        &self,
        customer_id: &str,
    ) -> Result<Vec<PaymentMethod>, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/payment_methods", self.base_url);
        
        let mut form_data = HashMap::new();
        form_data.insert("customer".to_string(), customer_id.to_string());
        form_data.insert("type".to_string(), "card".to_string());

        let response = self
            .client
            .get(&url)
            .basic_auth(&self.secret_key, Some(""))
            .query(&form_data)
            .send()
            .await?;

        if response.status().is_success() {
            #[derive(Deserialize)]
            struct PaymentMethodsList {
                data: Vec<PaymentMethod>,
            }
            
            let list: PaymentMethodsList = response.json().await?;
            Ok(list.data)
        } else {
            let error_text = response.text().await?;
            Err(format!("Stripe API Error: {}", error_text).into())
        }
    }

    pub async fn detach_payment_method(
        &self,
        payment_method_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/payment_methods/{}/detach", self.base_url, payment_method_id);

        let response = self
            .client
            .post(&url)
            .basic_auth(&self.secret_key, Some(""))
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error_text = response.text().await?;
            Err(format!("Stripe API Error: {}", error_text).into())
        }
    }
}