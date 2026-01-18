# Abstract
Tripwire models a goal-driven attack flow state machine. It orchestrates mutation of `Fuzzable` datagrams based on `Response` evaluation, advancing through steps until a goal is reached.
## Core Traits
### `Tripwire`
```rust
pub trait Tripwire {
    /// Datagram type sent to target
    type Input: Fuzzable;
    
    /// Datagram type received from target
    type Output: Response;
    
    /// Unique identifier for this tripwire (from spec)
    fn id(&self) -> TripwireId;
    
    /// Current step in the attack flow
    fn current_step(&self) -> StepId;
    
    /// Get field IDs to mutate for current step
    fn mutation_fields(&self) -> &[FieldId];
    
    /// Evaluate a response and determine next action
    fn evaluate(&mut self, response: &Self::Output) -> StepResult;
    
    /// Handle timeout (no response received)
    fn timeout(&mut self) -> StepResult;
    
    /// Check if goal has been reached
    fn goal(&self) -> Option<GoalId>;
    
    /// Get current seed
    fn seed(&self) -> u64;
    
    /// Advance seed and return new value
    fn next_seed(&mut self) -> u64;
    
    /// Reset to initial state (keeps initial seed)
    fn reset(&mut self);
    
    /// Reset with new seed
    fn reset_with_seed(&mut self, seed: u64);
}
```
### `TripwireBuilder`
Constructs tripwire from spec or programmatically.
```rust
pub trait TripwireBuilder: Sized {
    type Tripwire: Tripwire;
    
    /// Create from parsed spec
    fn from_spec(spec: &TripwireSpec) -> Result<Self, TripwireError>;
    
    /// Set initial seed
    fn seed(self, seed: u64) -> Self;
    
    /// Build the tripwire
    fn build(self) -> Self::Tripwire;
}
```
## Supporting Types
### Identifiers
```rust
/// Tripwire identifier (from spec: tripwires.<Name>)
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TripwireId(pub String);

/// Step identifier (from spec: steps.id)
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct StepId(pub u8);

/// Goal identifier (from spec: goals.id)
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GoalId(pub String);

/// Field identifier (from spec: fields.id)
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct FieldId(pub u16);
```
### Step Result
Returned by `evaluate()` and `timeout()`.
```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepResult {
    /// Retry current step with new mutation
    Stay,
    
    /// Advance to specified step
    Advance(StepId),
    
    /// Goal reached
    Goal(GoalId),
}
```
### Match Condition
Used internally for response evaluation.
```rust
#[derive(Clone, Debug)]
pub enum MatchCondition {
    Eq(FieldValue),
    Neq(FieldValue),
    Range { min: FieldValue, max: FieldValue },
    OneOf(Vec<FieldValue>),
    Any,
}

#[derive(Clone, Debug)]
pub struct FieldMatch {
    pub field: FieldId,
    pub condition: MatchCondition,
}
```
### Step Definition
Internal representation of a tripwire step.
```rust
#[derive(Clone, Debug)]
pub struct StepDef {
    pub id: StepId,
    pub match_criteria: Vec<FieldMatch>,  // AND logic
    pub mutate_fields: Vec<FieldId>,
    pub on_match: BranchAction,
    pub on_fail: BranchAction,
}

#[derive(Clone, Debug)]
pub enum BranchAction {
    Stay,
    Advance(StepId),
    Goal(GoalId),
    Branch(Vec<ConditionalBranch>),
}

#[derive(Clone, Debug)]
pub struct ConditionalBranch {
    pub condition: Option<Vec<FieldMatch>>,  // None = else
    pub action: Box<BranchAction>,
}
```
### Goal Definition
```rust
#[derive(Clone, Debug)]
pub struct GoalDef {
    pub id: GoalId,
    pub on_timeout: bool,
}
```
### Errors
```rust
#[derive(Debug)]
pub enum TripwireError {
    /// Referenced step does not exist
    InvalidStep(StepId),
    
    /// Referenced goal does not exist
    InvalidGoal(GoalId),
    
    /// Referenced field does not exist in input/output
    InvalidField(FieldId),
    
    /// Input struct not found in spec
    InputNotFound(String),
    
    /// Output struct not found in spec
    OutputNotFound(String),
    
    /// Circular step references
    CyclicSteps(Vec<StepId>),
    
    /// No steps defined
    NoSteps,
    
    /// No goals defined
    NoGoals,
}
```
## State Container
Reference implementation struct.
```rust
pub struct TripwireState<I: Fuzzable, O: Response> {
    id: TripwireId,
    steps: Vec<StepDef>,
    goals: Vec<GoalDef>,
    current_step: StepId,
    reached_goal: Option<GoalId>,
    seed: u64,
    initial_seed: u64,
    _phantom: PhantomData<(I, O)>,
}
```
## Evaluation Logic
### `evaluate()` Pseudocode
```
fn evaluate(response):
    step = get_step(current_step)
    
    # Check all match criteria (AND)
    all_match = true
    for criterion in step.match_criteria:
        value = response.get_field(criterion.field)
        if not criterion.condition.matches(value):
            all_match = false
            break
    
    # Determine action
    if all_match:
        action = step.on_match
    else:
        action = step.on_fail
    
    # Resolve action (may be conditional branch)
    return resolve_action(action, response)

fn resolve_action(action, response):
    match action:
        Stay => StepResult::Stay
        Advance(id) => 
            current_step = id
            StepResult::Advance(id)
        Goal(id) =>
            reached_goal = Some(id)
            StepResult::Goal(id)
        Branch(branches) =>
            for branch in branches:
                if branch.condition is None:  # else
                    return resolve_action(branch.action, response)
                if all_match(branch.condition, response):
                    return resolve_action(branch.action, response)
            StepResult::Stay  # fallback
```
### `timeout()` Pseudocode
```
fn timeout():
    for goal in goals:
        if goal.on_timeout:
            reached_goal = Some(goal.id)
            return StepResult::Goal(goal.id)
    
    StepResult::Stay
```
## Integration Points
### With `Fuzzable`
```rust
fn prepare_input(&mut self, input: &mut Self::Input) {
    for field_id in self.mutation_fields() {
        input.mutate_field(*field_id, self.next_seed());
    }
    input.compute_all();
}
```
### With `hurtbreak-trace`
```rust
pub trait TraceableTripwire: Tripwire {
    /// Record step transition to trace
    fn record_step(&self, writer: &mut TraceWriter) -> Result<(), TraceError>;
    
    /// Record goal reached to trace
    fn record_goal(&self, writer: &mut TraceWriter) -> Result<(), TraceError>;
    
    /// Extract matched field values for trace (trimmed format)
    fn matched_fields(&self, response: &Self::Output) -> Vec<(FieldId, FieldValue)>;
}
```

---

## Derive Macro

From `hurtbreak-derive`, generates impl from annotated struct:
```rust
#[derive(Tripwire)]
#[tripwire(id = "Handshake", input = "Request", output = "Response")]
pub struct HandshakeTripwire {
    // State managed by macro
}
```

Or fully generated from spec.toml via `build.rs` with no user struct.

---

## C FFI Mapping

| Rust | C |
|------|---|
| `Tripwire::current_step()` | `uint8_t hb_tripwire_<Name>_current_step(...)` |
| `Tripwire::evaluate()` | `hb_step_result_t hb_tripwire_<Name>_evaluate(...)` |
| `Tripwire::timeout()` | `hb_step_result_t hb_tripwire_<Name>_timeout(...)` |
| `Tripwire::goal()` | `uint8_t hb_tripwire_<Name>_goal(...)` |
| `Tripwire::mutation_fields()` | `size_t hb_tripwire_<Name>_mutation_fields(..., uint16_t* out)` |
| `Tripwire::reset()` | `void hb_tripwire_<Name>_reset(...)` |
| `StepResult::Stay` | `HB_STEP_STAY` |
| `StepResult::Advance` | `HB_STEP_ADVANCE` |
| `StepResult::Goal` | `HB_STEP_GOAL` |

---

## Constraints

| Constraint | Limit | Reason |
|------------|-------|--------|
| Max steps | 255 | `StepId(u8)` |
| Max goals | 255 | `u8` in trace format |
| Max fields per step | 255 | `u8` count in trace |
| Max match criteria per step | No limit | Vec |
| Max branches per action | No limit | Vec |

---

## Usage Example
```rust
// From spec
let spec = parse_spec_file("spec.toml")?;
let tripwire = TripwireState::<Request, Response>::from_spec(&spec.tripwires["Handshake"])?
    .seed(0xDEADBEEF)
    .build();

// Main loop
let mut request = Request::default();
loop {
    tripwire.prepare_input(&mut request);
    transport.send(&request.serialize())?;
    
    let result = match transport.recv_timeout(Duration::from_secs(1)) {
        Ok(bytes) => {
            let response = Response::deserialize(&bytes)?;
            tripwire.evaluate(&response)
        }
        Err(Timeout) => tripwire.timeout(),
    };
    
    match result {
        StepResult::Stay => continue,
        StepResult::Advance(step) => {
            trace.record_step(&tripwire)?;
            continue;
        }
        StepResult::Goal(goal) => {
            trace.record_goal(&tripwire)?;
            break;
        }
    }
}
```