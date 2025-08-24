use anyhow::Result;
use std::time::Duration;

#[cfg(feature = "async")]
use async_trait::async_trait;

#[derive(Debug)]pub enum AttackResult<T> {
    Ok(T),
    Continue(anyhow::Error),
    Stop(anyhow::Error),
}

impl<T> AttackResult<T> {
    pub fn is_ok(&self) -> bool {
        matches!(self, AttackResult::Ok(_))
    }
    
    pub fn is_continue(&self) -> bool {
        matches!(self, AttackResult::Continue(_))
    }
    
    pub fn is_stop(&self) -> bool {
        matches!(self, AttackResult::Stop(_))
    }
    
    pub fn should_continue(&self) -> bool {
        matches!(self, AttackResult::Continue(_))
    }
    
    pub fn unwrap(self) -> T {
        match self {
            AttackResult::Ok(value) => value,
            AttackResult::Continue(err) => panic!("called `AttackResult::unwrap()` on a `Continue` value: {}", err),
            AttackResult::Stop(err) => panic!("called `AttackResult::unwrap()` on a `Stop` value: {}", err),
        }
    }
    
    pub fn map<U, F>(self, f: F) -> AttackResult<U>
    where
        F: FnOnce(T) -> U,
    {
        match self {
            AttackResult::Ok(value) => AttackResult::Ok(f(value)),
            AttackResult::Continue(err) => AttackResult::Continue(err),
            AttackResult::Stop(err) => AttackResult::Stop(err),
        }
    }
}

pub trait Attack {
    type Response;
    
    fn send_payload(&self, payload: &[u8]) -> AttackResult<()>;
    
    fn wait_for_response(&self, timeout: Duration) -> AttackResult<Self::Response>;
    
    fn validate_response(&self, response: &Self::Response) -> AttackResult<()>;
    
    fn execute_attack(&self, payload: &[u8]) -> AttackResult<Self::Response> {
        // Send payload
        match self.send_payload(payload) {
            AttackResult::Ok(()) => {},
            result => return result.map(|_| unreachable!()),
        }
        
        // Wait for response
        let timeout = Duration::from_secs(5); // Default timeout
        let response = match self.wait_for_response(timeout) {
            AttackResult::Ok(response) => response,
            result => return result,
        };
        
        // Validate response and return the response if validation passes
        match self.validate_response(&response) {
            AttackResult::Ok(()) => AttackResult::Ok(response),
            AttackResult::Continue(err) => AttackResult::Continue(err),
            AttackResult::Stop(err) => AttackResult::Stop(err),
        }
    }
    
    fn validate_payload(&self, payload: &[u8]) -> Result<()> {
        if payload.is_empty() {
            anyhow::bail!("Payload cannot be empty");
        }
        Ok(())
    }
    
    fn prepare(&mut self) -> Result<()> {
        Ok(())
    }
    
    fn cleanup(&mut self) -> Result<()> {
        Ok(())
    }
    
    fn get_target_info(&self) -> String {
        "Generic Attack Target".to_string()
    }
}

#[cfg(feature = "async")]
#[async_trait]
pub trait AsyncAttack {
    type Response: Send;
    
    async fn send_payload(&self, payload: &[u8]) -> AttackResult<()>;
    
    async fn wait_for_response(&self, timeout: Duration) -> AttackResult<Self::Response>;
    
    async fn validate_response(&self, response: &Self::Response) -> AttackResult<()>;
    
    async fn execute_attack(&self, payload: &[u8]) -> AttackResult<Self::Response> {
        // Send payload
        match self.send_payload(payload).await {
            AttackResult::Ok(()) => {},
            result => return result.map(|_| unreachable!()),
        }
        
        // Wait for response
        let timeout = Duration::from_secs(5); // Default timeout
        let response = match self.wait_for_response(timeout).await {
            AttackResult::Ok(response) => response,
            result => return result,
        };
        
        // Validate response and return the response if validation passes
        match self.validate_response(&response).await {
            AttackResult::Ok(()) => AttackResult::Ok(response),
            AttackResult::Continue(err) => AttackResult::Continue(err),
            AttackResult::Stop(err) => AttackResult::Stop(err),
        }
    }
    
    async fn validate_payload(&self, payload: &[u8]) -> anyhow::Result<()> {
        if payload.is_empty() {
            anyhow::bail!("Payload cannot be empty");
        }
        Ok(())
    }
    
    async fn prepare(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
    
    async fn cleanup(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
    
    fn get_target_info(&self) -> String {
        "Generic Async Attack Target".to_string()
    }
}