use std::collections::HashMap;

use actix_web::dev;
// Add these methods to your StripeClient impl block
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::fs;
use std::path::Path;


use crate::error::{AppError, Result as AppResult};

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

#[derive(Debug, Serialize, Deserialize)]
pub struct PaymentIntent {
    pub id: String,
    pub client_secret: String,
    pub status: String,
    pub amount: i64,
    pub currency: String,
    pub payment_method: Option<String>,
    pub metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Charge {
    pub id: String,
    pub amount: i64,
    pub currency: String,
    pub status: String,
    pub paid: bool,
    pub refunded: bool,
    pub customer: Option<String>,
    pub payment_method: Option<String>,
    pub metadata: Option<HashMap<String, String>>,
    pub created: i64,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Refund {
    pub id: String,
    pub amount: i64,
    pub currency: String,
    pub charge: String,
    pub status: String,
    pub reason: Option<String>,
    pub metadata: Option<HashMap<String, String>>,
    pub created: i64,
}

// Add the StripeClient struct definition (unchanged)
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



/// Charge a payment method for a specific amount
    /// 
    /// # Arguments
    /// * `amount` - Amount in smallest currency unit (e.g., cents for USD)
    /// * `currency` - ISO 4217 currency code (e.g., "usd", "aud")
    /// * `payment_method_id` - The payment method to charge
    /// * `customer_id` - Optional customer ID
    /// * `transaction_id` - Your internal transaction ID
    /// * `school_id` - Your internal school ID
    /// * `user_id` - Your internal user ID
    /// * `description` - Optional description for the charge
    pub async fn charge_payment_method (
        &self,
        amount: i64,
        currency: &str,
        payment_method_id: &String,
        customer_id: &String,
        transaction_id: &Uuid,
        school_id: &Uuid,
        user_id: &Uuid,
        description: Option<&String>,
    ) -> AppResult<PaymentIntent> {
        let url = format!("{}/payment_intents", self.base_url);
        
        let mut form_data = HashMap::new();
        form_data.insert("amount".to_string(), amount.to_string());
        form_data.insert("currency".to_string(), currency.to_string());
        form_data.insert("payment_method".to_string(), payment_method_id.to_string());
        form_data.insert("confirm".to_string(), "true".to_string());
        form_data.insert("off_session".to_string(), "true".to_string());
        
        // if let Some(customer) = customer_id {
            form_data.insert("customer".to_string(), customer_id.clone());
        // }

        if let Some(desc) = description {
            form_data.insert("description".to_string(), desc.to_string());
        }

        // Add metadata
        form_data.insert("metadata[transaction_id]".to_string(), transaction_id.to_string());
        form_data.insert("metadata[school_id]".to_string(), school_id.to_string());
        form_data.insert("metadata[user_id]".to_string(), user_id.to_string());

        let response = self
            .client
            .post(&url)
            .basic_auth(&self.secret_key, Some(""))
            .form(&form_data)
            .send()
            .await
            .map_err(| e| AppError::Internal("Failed to charge customer payment method".to_string()))?;

        if response.status().is_success() {
            let payment_intent: PaymentIntent = response.json().await.map_err(|e| AppError::Internal(format!("Json error stripe")))?;
            Ok(payment_intent)
        } else {
            let error_text = response.text().await.map_err(|e| AppError::Internal(format!("Json2 error stripe")))?;
            Err (AppError::Internal(format!("Stripe API Error: {}", error_text).into()))
        }
    }

    /// Get all charges for a specific customer
    /// 
    /// # Arguments
    /// * `customer_id` - The customer ID to get charges for
    /// * `limit` - Optional limit (default 10, max 100)
    pub async fn list_customer_charges(
        &self,
        customer_id: &str,
        limit: Option<i32>,
    ) -> Result<Vec<Charge>, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/charges", self.base_url);
        
        let mut query_params = HashMap::new();
        query_params.insert("customer".to_string(), customer_id.to_string());
        
        if let Some(limit_val) = limit {
            let clamped_limit = limit_val.clamp(1, 100);
            query_params.insert("limit".to_string(), clamped_limit.to_string());
        } else {
            query_params.insert("limit".to_string(), "10".to_string());
        }

        let response = self
            .client
            .get(&url)
            .basic_auth(&self.secret_key, Some(""))
            .query(&query_params)
            .send()
            .await?;

        if response.status().is_success() {
            #[derive(Deserialize)]
            struct ChargesList {
                data: Vec<Charge>,
            }
            
            let list: ChargesList = response.json().await?;
            Ok(list.data)
        } else {
            let error_text = response.text().await?;
            Err(format!("Stripe API Error: {}", error_text).into())
        }
    }

    /// Refund a charge either partially or completely
    /// 
    /// # Arguments
    /// * `charge_id` - The charge ID to refund
    /// * `amount` - Optional amount to refund (if None, refunds the full amount)
    /// * `reason` - Optional reason for the refund ("duplicate", "fraudulent", "requested_by_customer")
    /// * `metadata` - Optional metadata for the refund
    pub async fn refund_charge(
        &self,
        charge_id: &str,
        amount: Option<i64>,
        reason: Option<&str>,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<Refund, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/refunds", self.base_url);
        
        let mut form_data = HashMap::new();
        form_data.insert("charge".to_string(), charge_id.to_string());
        
        if let Some(refund_amount) = amount {
            form_data.insert("amount".to_string(), refund_amount.to_string());
        }

        if let Some(refund_reason) = reason {
            // Validate reason is one of the allowed values
            match refund_reason {
                "duplicate" | "fraudulent" | "requested_by_customer" => {
                    form_data.insert("reason".to_string(), refund_reason.to_string());
                }
                _ => {
                    return Err("Invalid refund reason. Must be 'duplicate', 'fraudulent', or 'requested_by_customer'".into());
                }
            }
        }

        // Add metadata if provided
        if let Some(meta) = metadata {
            for (key, value) in meta {
                form_data.insert(format!("metadata[{}]", key), value);
            }
        }

        let response = self
            .client
            .post(&url)
            .basic_auth(&self.secret_key, Some(""))
            .form(&form_data)
            .send()
            .await?;

        if response.status().is_success() {
            let refund: Refund = response.json().await?;
            Ok(refund)
        } else {
            let error_text = response.text().await?;
            Err(format!("Stripe API Error: {}", error_text).into())
        }
    }

    /// Convenience method to refund a charge completely
    pub async fn refund_charge_full(
        &self,
        charge_id: &str,
        reason: Option<&str>,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<Refund, Box<dyn std::error::Error + Send + Sync>> {
        self.refund_charge(charge_id, None, reason, metadata).await
    }

    /// Convenience method to refund a charge partially
    pub async fn refund_charge_partial(
        &self,
        charge_id: &str,
        amount: i64,
        reason: Option<&str>,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<Refund, Box<dyn std::error::Error + Send + Sync>> {
        self.refund_charge(charge_id, Some(amount), reason, metadata).await
    }

}