use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use std::time::SystemTime;

use crate::error::{AppError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Permissions {
    HyperAdmin,
    SuperAdmin,
    ClubAdmin,
    ClassAdmin,
    HeadInstructor,
    Instructor,
    AssistantInstructor, 
    Student,
}

// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct User {
//     #[serde(flatten)]
//     items: HashMap<String, i32>,
//     #[serde(default)]
//     reserved_items: HashMap<String, i32>,
// }

// impl StockLevel {
//     pub fn new() -> Self {
//         Self {
//             items: HashMap::new(),
//             reserved_items: HashMap::new(),
//         }
//     }
    
//     pub fn get_stock(&self, item_id: &str) -> i32 {
//         *self.items.get(item_id).unwrap_or(&0)
//     }
    
//     pub fn get_available_stock(&self, item_id: &str) -> i32 {
//         let total = self.get_stock(item_id);
//         let reserved = self.get_reserved(item_id);
//         total - reserved
//     }
    
//     pub fn get_reserved(&self, item_id: &str) -> i32 {
//         *self.reserved_items.get(item_id).unwrap_or(&0)
//     }
    
//     pub fn set_stock(&mut self, item_id: &str, level: i32) -> Result<()> {
//         let reserved = self.get_reserved(item_id);
        
//         if level < reserved {
//             return Err(AppError::InsufficientStock(format!(
//                 "Cannot set stock level below reserved amount. Item: {}, Requested: {}, Reserved: {}",
//                 item_id, level, reserved
//             )));
//         }
        
//         self.items.insert(item_id.to_string(), level);
//         Ok(())
//     }
    
//     pub fn update_stock(&mut self, item_id: &str, change: i32) -> Result<()> {
//         let current = self.get_stock(item_id);
//         let new_value = current + change;
        
//         if new_value < 0 {
//             return Err(AppError::StockNotAvailable);
//         }
        
//         self.items.insert(item_id.to_string(), new_value);
//         Ok(())
//     }
    
//     pub fn reserve_stock(&mut self, item_id: &str, quantity: i32) -> Result<()> {
//         if quantity <= 0 {
//             return Ok(());  // Nothing to reserve
//         }
        
//         let available = self.get_available_stock(item_id);
//         if available < quantity {
//             return Err(AppError::InsufficientStock(format!(
//                 "Not enough available stock. Item: {}, Requested: {}, Available: {}",
//                 item_id, quantity, available
//             )));
//         }
        
//         let reserved = self.get_reserved(item_id);
//         self.reserved_items.insert(item_id.to_string(), reserved + quantity);
        
//         Ok(())
//     }
    
//     pub fn unreserve_stock(&mut self, item_id: &str, quantity: i32) -> Result<()> {
//         if quantity <= 0 {
//             return Ok(());  // Nothing to unreserve
//         }
        
//         let reserved = self.get_reserved(item_id);
//         if reserved < quantity {
//             return Err(AppError::Internal(format!(
//                 "Cannot unreserve more than reserved. Item: {}, Unreserve: {}, Reserved: {}",
//                 item_id, quantity, reserved
//             )));
//         }
        
//         self.reserved_items.insert(item_id.to_string(), reserved - quantity);
//         Ok(())
//     }
// }

