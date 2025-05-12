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


