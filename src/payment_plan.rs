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

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum  StatWindow {
    HOUR=1,
    DAY=2,
    WEEK=3,
    MONTH=4,
    YEAR=5,
    ALL=6,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StatGender {
    Male=1,
    Female=2,
    Unknown=3,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StatPayType {
    FreeLesson=1,
    AllPlan=2,
    FamilyPlan=3,
    IndividualPlan=4,
    Instructor=5,
    NoCharge=6,
}


#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StatCountType {
    AttendanceAll=1,
    AttendanceGender=2,
    AttendanceAge=3,
    AttendancePay=4,
    Revenue=5,
    PendingRevenue=6,
    Refunded=7,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StatIdType {
    SCHOOL=1,
    CLASS=2,
    VENUE=3,
    CLUB=4,
}