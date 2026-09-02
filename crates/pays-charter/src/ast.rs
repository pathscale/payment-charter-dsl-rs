//! The abstract syntax tree.
//!
//! Every node carries a span. Diagnostics that cannot point at the source are diagnostics a
//! controller cannot act on, and a charter is read by people who did not write it.

use crate::lex::Span;
use charter_assetref::AssetRef;

#[derive(Clone, Debug)]
pub struct Spanned<T> {
    pub node: T,
    pub span: Span,
}

impl<T> Spanned<T> {
    pub fn new(node: T, span: Span) -> Self {
        Self { node, span }
    }
}

pub type Name = Spanned<String>;

#[derive(Clone, Debug)]
pub struct Charter {
    pub name: Name,
    pub version: u64,
    pub extends: Option<(Name, u64)>,
    pub resolver_tier: Spanned<String>,
    pub resolver_version: u64,
    pub timezone: Spanned<String>,
    pub decls: Vec<Decl>,
}

#[derive(Clone, Debug)]
pub enum Decl {
    Asset(AssetDecl),
    AssetGroup(AssetGroupDecl),
    Instrument(InstrumentDecl),
    Group(GroupDecl),
    Approvers(ApproversDecl),
    Prohibit(ProhibitDecl),
    Limit(LimitDecl),
}

impl Decl {
    pub fn name(&self) -> &Name {
        match self {
            Decl::Asset(d) => &d.name,
            Decl::AssetGroup(d) => &d.name,
            Decl::Instrument(d) => &d.name,
            Decl::Group(d) => &d.name,
            Decl::Approvers(d) => &d.name,
            Decl::Prohibit(d) => &d.name,
            Decl::Limit(d) => &d.name,
        }
    }

    /// The kind a use site can require (S28). Sorting order for §1.1's canonical form is the
    /// order of these variants.
    pub fn kind(&self) -> Kind {
        match self {
            Decl::Asset(_) => Kind::Asset,
            Decl::AssetGroup(_) => Kind::AssetGroup,
            Decl::Instrument(_) => Kind::Instrument,
            Decl::Group(_) => Kind::Group,
            Decl::Approvers(_) => Kind::Approvers,
            Decl::Prohibit(_) => Kind::Prohibit,
            Decl::Limit(_) => Kind::Limit,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Asset,
    AssetGroup,
    Instrument,
    Group,
    Approvers,
    Prohibit,
    Limit,
}

impl Kind {
    pub fn describe(self) -> &'static str {
        match self {
            Kind::Asset => "an asset",
            Kind::AssetGroup => "an asset group",
            Kind::Instrument => "an instrument",
            Kind::Group => "a group",
            Kind::Approvers => "an approver set",
            Kind::Prohibit => "a prohibition",
            Kind::Limit => "a limit",
        }
    }
}

#[derive(Clone, Debug)]
pub struct AssetDecl {
    pub name: Name,
    pub reference: Spanned<AssetRef>,
}

#[derive(Clone, Debug)]
pub struct AssetGroupDecl {
    pub name: Name,
    pub members: Vec<Name>,
}

#[derive(Clone, Debug)]
pub struct InstrumentDecl {
    pub name: Name,
    pub reference: Spanned<InstrumentRef>,
}

/// `card://visa/tok_a1b2c3` or `wallet://solana:…/7xKX…`. The handle is an opaque,
/// non-secret identifier; S26 forbids a credential here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstrumentRef {
    Card { network: String, handle: String },
    Wallet { chain: String, address: String },
}

impl InstrumentRef {
    /// What an instrument's name must begin with under S27.
    pub fn prefix(&self) -> &str {
        match self {
            InstrumentRef::Card { network, .. } => network,
            InstrumentRef::Wallet { chain, .. } => {
                chain.split(':').next().unwrap_or(chain)
            }
        }
    }

    pub fn handle(&self) -> &str {
        match self {
            InstrumentRef::Card { handle, .. } => handle,
            InstrumentRef::Wallet { address, .. } => address,
        }
    }
}

impl core::fmt::Display for InstrumentRef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InstrumentRef::Card { network, handle } => write!(f, "card://{network}/{handle}"),
            InstrumentRef::Wallet { chain, address } => write!(f, "wallet://{chain}/{address}"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct GroupDecl {
    pub name: Name,
    pub members: Vec<Spanned<Literal>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Literal {
    Address(String),
    /// `mcc:5411`, `country:PRK`, `class:fiat_reserve`.
    Tagged(String, String),
}

impl Literal {
    /// Each tag belongs to exactly one field (§2.11), which is what E303 checks.
    pub fn tag(&self) -> &str {
        match self {
            Literal::Address(_) => "address",
            Literal::Tagged(t, _) => t,
        }
    }
}

impl core::fmt::Display for Literal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Literal::Address(a) => f.write_str(a),
            Literal::Tagged(t, v) => write!(f, "{t}:{v}"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ApproversDecl {
    pub name: Name,
    pub members: Vec<Name>,
}

#[derive(Clone, Debug)]
pub struct ProhibitDecl {
    pub name: Name,
    pub condition: Condition,
}

#[derive(Clone, Debug)]
pub struct LimitDecl {
    pub name: Name,
    pub dimension: Dimension,
    /// The `for` clause (S23). `None` means the limit applies to every request in its asset.
    pub applies: Option<Condition>,
    pub window: Spanned<Window>,
    pub scope: Option<Spanned<Scope>>,
    pub escalations: Vec<Escalation>,
}

#[derive(Clone, Debug)]
pub enum Dimension {
    Amount { base: Spanned<Money>, exceptions: Vec<Exception> },
    Count { base: Spanned<u64>, exceptions: Vec<Exception> },
}

impl Dimension {
    pub fn asset(&self) -> Option<&Name> {
        match self {
            Dimension::Amount { base, .. } => Some(&base.node.asset),
            Dimension::Count { .. } => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Money {
    /// Digits as written, before minor-unit conversion — the resolver supplies `decimals`,
    /// so the conversion cannot happen until the asset resolves (§2.6).
    pub integer: u64,
    pub fraction: String,
    pub asset: Name,
}

#[derive(Clone, Debug)]
pub struct Exception {
    pub value: Spanned<ExcValue>,
    pub condition: Condition,
}

#[derive(Clone, Debug)]
pub enum ExcValue {
    Money(Money),
    Count(u64),
    /// Legal only in a charter that extends another (E314); resolves to the parent's ceiling.
    Unlimited,
}

#[derive(Clone, Debug)]
pub enum Window {
    Rolling { seconds: u64, unit: String, count: u64 },
    Fixed { unit: String, tz: Option<String> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Account,
    Agent,
    Instrument,
    Counterparty,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Account => "account",
            Scope::Agent => "agent",
            Scope::Instrument => "instrument",
            Scope::Counterparty => "counterparty",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Escalation {
    pub trigger: Spanned<Trigger>,
    pub quorum: Spanned<u64>,
    pub approvers: Name,
    pub ceiling: Spanned<ExcValue>,
    pub within: Option<Spanned<u64>>,
    pub within_text: Option<(u64, String)>,
}

#[derive(Clone, Debug)]
pub enum Trigger {
    /// `above V` fires on `requested > V`.
    Above(Money),
    /// `at least V` fires on `requested >= V`. Both exist because English does not agree
    /// with itself and the difference is one payment (§8.2.3).
    AtLeast(Money),
    AboveCount(u64),
    AtLeastCount(u64),
    WhenExhausted,
}

impl Trigger {
    /// S17: `above` and `at least` are the same trigger kind, so a limit may carry only one.
    pub fn kind(&self) -> &'static str {
        match self {
            Trigger::Above(_) | Trigger::AtLeast(_) => "threshold",
            Trigger::AboveCount(_) | Trigger::AtLeastCount(_) => "threshold",
            Trigger::WhenExhausted => "exhausted",
        }
    }
}

#[derive(Clone, Debug)]
pub enum Condition {
    Or(Box<Condition>, Box<Condition>),
    And(Box<Condition>, Box<Condition>),
    Not(Box<Condition>),
    Compare(Comparison),
}

#[derive(Clone, Debug)]
pub struct Comparison {
    pub field: Spanned<String>,
    pub operator: Spanned<String>,
    pub value: Spanned<Value>,
}

#[derive(Clone, Debug)]
pub enum Value {
    /// A reference to a declaration: an asset, an instrument, or a group.
    Named(String),
    Literal(Literal),
    Date(String),
    Plane(String),
    Set(Vec<Spanned<Value>>),
}
