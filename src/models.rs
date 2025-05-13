use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use std::time::SystemTime;

use crate::error::{AppError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Permissions {
    HyperAdmin,
    SuperAdmin,
    CreateSuperAdmin,
    RemoveSuperAdmin,
    CreateClass,
    ModifyClass,
    RemoveClass,
    InstructClass,
    ViewClass,
    CreateClub,
    ViewClub,
    ModifyClub,
    RemoveClub,
    CreateWaiver,
    AddStudent,
    RemoveStudent,
    ViewStudent,
    ModifyStudent,
    SendEmail,
    CreateInstructor,
    ModifyInstructor,
    RemoveInstructor,
    ViewInstructor,
    CreateGrading,
    ModifyGrading,
    RemoveGrading,
    ViewGrading,
    RefundPayment,
    DiscountStudent,
    CreateDiscount,
    ModifyDiscount,
    RemoveDiscount,
    ViewAllUsers,
    Banned,
}


