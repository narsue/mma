use serde::{Serialize, Deserialize};

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaymentPlanDuration {
    SingleClass=0,
    CalenderMonth=1,
    SchoolTerm=2,
    END=3,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaymentGroupType {
    Individual=0,
    Family=1,
    END=2,
}
