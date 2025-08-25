use anyhow::Result;
use std::time::Duration;

#[cfg(feature = "async")]
use async_trait::async_trait;

/// Result type for attack operations with flow control semantics.
/// 
/// This enum represents the outcome of an attack operation and provides
/// flow control information to determine whether the attack should continue,
/// stop, or has succeeded.
/// 
/// # Variants
/// 
/// * `Ok(T)` - The operation completed successfully with result `T`
/// * `Continue(Error)` - The operation failed but the attack should continue with the next attempt
/// * `Stop(Error)` - The operation failed and the attack should stop immediately
/// 
/// # Examples
/// 
/// ```rust,norun
/// use hurtbreak_core::attack::AttackResult;
/// use anyhow::anyhow;
/// 
/// fn process_response(valid: bool) -> AttackResult<String> {
///     if valid {
///         AttackResult::Ok("Success".to_string())
///     } else {
///         AttackResult::Continue(anyhow!("Invalid response, trying next"))
///     }
/// }
/// 
/// match process_response(false) {
///     AttackResult::Ok(result) => println!("Attack succeeded: {}", result),
///     AttackResult::Continue(err) => println!("Continuing attack: {}", err),
///     AttackResult::Stop(err) => println!("Attack stopped: {}", err),
/// }
/// ```
#[derive(Debug)]
pub enum AttackResult<T> {
    /// Operation completed successfully with the given result.
    Ok(T),
    /// Operation failed but attack should continue with next attempt.
    Continue(anyhow::Error),
    /// Operation failed and attack should stop immediately.
    Stop(anyhow::Error),
}

impl<T> AttackResult<T> {
    /// Returns `true` if the result is `Ok`.
    /// 
    /// # Examples
    /// 
    /// ```rust,norun
    /// use hurtbreak_core::attack::AttackResult;
    /// 
    /// let result: AttackResult<i32> = AttackResult::Ok(42);
    /// assert!(result.is_ok());
    /// ```
    pub fn is_ok(&self) -> bool {
        matches!(self, AttackResult::Ok(_))
    }
    
    /// Returns `true` if the result is `Continue`.
    /// 
    /// # Examples
    /// 
    /// ```rust,norun
    /// use hurtbreak_core::attack::AttackResult;
    /// use anyhow::anyhow;
    /// 
    /// let result: AttackResult<i32> = AttackResult::Continue(anyhow!("try again"));
    /// assert!(result.is_continue());
    /// ```
    pub fn is_continue(&self) -> bool {
        matches!(self, AttackResult::Continue(_))
    }
    
    /// Returns `true` if the result is `Stop`.
    /// 
    /// # Examples
    /// 
    /// ```rust,norun
    /// use hurtbreak_core::attack::AttackResult;
    /// use anyhow::anyhow;
    /// 
    /// let result: AttackResult<i32> = AttackResult::Stop(anyhow!("fatal error"));
    /// assert!(result.is_stop());
    /// ```
    pub fn is_stop(&self) -> bool {
        matches!(self, AttackResult::Stop(_))
    }
    
    /// Returns `true` if the attack should continue (i.e., result is `Continue`).
    /// 
    /// This is an alias for `is_continue()` that may be more semantically clear
    /// in attack flow control contexts.
    /// 
    /// # Examples
    /// 
    /// ```rust,norun
    /// use hurtbreak_core::attack::AttackResult;
    /// use anyhow::anyhow;
    /// 
    /// let result: AttackResult<i32> = AttackResult::Continue(anyhow!("keep trying"));
    /// if result.should_continue() {
    ///     println!("Continuing with next attack iteration");
    /// }
    /// ```
    pub fn should_continue(&self) -> bool {
        matches!(self, AttackResult::Continue(_))
    }
    
    /// Unwraps the contained `Ok` value, panicking if the result is not `Ok`.
    /// 
    /// # Panics
    /// 
    /// Panics with the error message if the result is `Continue` or `Stop`.
    /// 
    /// # Examples
    /// 
    /// ```rust,norun
    /// use hurtbreak_core::attack::AttackResult;
    /// 
    /// let result: AttackResult<i32> = AttackResult::Ok(42);
    /// assert_eq!(result.unwrap(), 42);
    /// ```
    pub fn unwrap(self) -> T {
        match self {
            AttackResult::Ok(value) => value,
            AttackResult::Continue(err) => panic!("called `AttackResult::unwrap()` on a `Continue` value: {}", err),
            AttackResult::Stop(err) => panic!("called `AttackResult::unwrap()` on a `Stop` value: {}", err),
        }
    }
    
    /// Maps an `AttackResult<T>` to `AttackResult<U>` by applying a function to the contained `Ok` value.
    /// 
    /// The function is only applied if the result is `Ok`. `Continue` and `Stop` variants
    /// are passed through unchanged.
    /// 
    /// # Examples
    /// 
    /// ```rust,norun
    /// use hurtbreak_core::attack::AttackResult;
    /// 
    /// let result: AttackResult<i32> = AttackResult::Ok(21);
    /// let doubled = result.map(|x| x * 2);
    /// 
    /// match doubled {
    ///     AttackResult::Ok(value) => assert_eq!(value, 42),
    ///     _ => panic!("Expected Ok"),
    /// }
    /// ```
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

/// Core trait for implementing synchronous attack protocols.
/// 
/// This trait defines the fundamental operations required for executing
/// attacks against a target system. It provides a structured approach to
/// sending payloads, receiving responses, and validating results.
/// 
/// # Associated Types
/// 
/// * `Response` - The type of response expected from the target system
/// 
/// # Examples
/// 
/// ```rust,norun
/// use hurtbreak_core::attack::{Attack, AttackResult};
/// use std::time::Duration;
/// use anyhow::anyhow;
/// 
/// struct SimpleAttack;
/// 
/// impl Attack for SimpleAttack {
///     type Response = Vec<u8>;
/// 
///     fn send_payload(&self, payload: &[u8]) -> AttackResult<()> {
///         if payload.is_empty() {
///             AttackResult::Continue(anyhow!("Empty payload"))
///         } else {
///             AttackResult::Ok(())
///         }
///     }
/// 
///     fn wait_for_response(&self, _timeout: Duration) -> AttackResult<Self::Response> {
///         AttackResult::Ok(vec![0x41, 0x42, 0x43])
///     }
/// 
///     fn validate_response(&self, response: &Self::Response) -> AttackResult<()> {
///         if response.len() > 0 {
///             AttackResult::Ok(())
///         } else {
///             AttackResult::Continue(anyhow!("Empty response"))
///         }
///     }
/// }
/// ```
pub trait Attack {
    /// The type of response expected from the attack target.
    type Response;
    
    /// Sends a payload to the target system.
    /// 
    /// This method transmits the attack payload to the target and returns
    /// an `AttackResult` indicating whether the transmission was successful,
    /// should be retried, or should be aborted.
    /// 
    /// # Arguments
    /// 
    /// * `payload` - The byte array containing the attack payload to send
    /// 
    /// # Returns
    /// 
    /// * `Ok(())` - Payload sent successfully
    /// * `Continue(error)` - Payload send failed, but attack should continue
    /// * `Stop(error)` - Payload send failed, attack should be aborted
    fn send_payload(&self, payload: &[u8]) -> AttackResult<()>;
    
    /// Waits for a response from the target system with a timeout.
    /// 
    /// This method blocks waiting for a response from the target system
    /// for up to the specified timeout duration.
    /// 
    /// # Arguments
    /// 
    /// * `timeout` - Maximum duration to wait for a response
    /// 
    /// # Returns
    /// 
    /// * `Ok(response)` - Response received successfully
    /// * `Continue(error)` - No response or invalid response, should retry
    /// * `Stop(error)` - Fatal error occurred, should abort
    fn wait_for_response(&self, timeout: Duration) -> AttackResult<Self::Response>;
    
    /// Validates the response received from the target system.
    /// 
    /// This method analyzes the response to determine if it indicates
    /// a successful attack, a failure that should be retried, or a
    /// fatal condition that should stop the attack.
    /// 
    /// # Arguments
    /// 
    /// * `response` - The response data to validate
    /// 
    /// # Returns
    /// 
    /// * `Ok(())` - Response validation successful, attack succeeded
    /// * `Continue(error)` - Response invalid but should retry
    /// * `Stop(error)` - Response indicates fatal error, should abort
    fn validate_response(&self, response: &Self::Response) -> AttackResult<()>;
    
    /// Executes a complete attack sequence with the given payload.
    /// 
    /// This method orchestrates the full attack flow: sending the payload,
    /// waiting for a response, and validating the result. The default
    /// implementation coordinates the other trait methods automatically.
    /// 
    /// # Arguments
    /// 
    /// * `payload` - The attack payload bytes to send
    /// 
    /// # Returns
    /// 
    /// * `Ok(response)` - Attack completed successfully with response
    /// * `Continue(error)` - Attack failed but should be retried
    /// * `Stop(error)` - Attack failed and should not be retried
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
    
    /// Validates an attack payload before sending.
    /// 
    /// This method performs pre-transmission validation of the payload
    /// to ensure it meets basic requirements and is suitable for the
    /// specific attack implementation.
    /// 
    /// # Arguments
    /// 
    /// * `payload` - The payload bytes to validate
    /// 
    /// # Returns
    /// 
    /// * `Ok(())` - Payload is valid and ready to send
    /// * `Err(error)` - Payload validation failed
    /// 
    /// # Examples
    /// 
    /// ```rust,norun
    /// use hurtbreak_core::attack::Attack;
    /// 
    /// struct MyAttack;
    /// impl Attack for MyAttack {
    ///     type Response = Vec<u8>;
    ///     // ... other required methods
    /// #     fn send_payload(&self, _: &[u8]) -> hurtbreak_core::attack::AttackResult<()> { unimplemented!() }
    /// #     fn wait_for_response(&self, _: std::time::Duration) -> hurtbreak_core::attack::AttackResult<Vec<u8>> { unimplemented!() }
    /// #     fn validate_response(&self, _: &Vec<u8>) -> hurtbreak_core::attack::AttackResult<()> { unimplemented!() }
    /// }
    /// 
    /// let attack = MyAttack;
    /// let payload = vec![0x01, 0x02, 0x03];
    /// assert!(attack.validate_payload(&payload).is_ok());
    /// ```
    fn validate_payload(&self, payload: &[u8]) -> Result<()> {
        if payload.is_empty() {
            anyhow::bail!("Payload cannot be empty");
        }
        Ok(())
    }
    
    /// Prepares the attack implementation for execution.
    /// 
    /// This method is called before attack execution begins and allows
    /// implementations to perform any necessary initialization, resource
    /// allocation, or setup operations.
    /// 
    /// # Returns
    /// 
    /// * `Ok(())` - Preparation completed successfully
    /// * `Err(error)` - Preparation failed
    fn prepare(&mut self) -> Result<()> {
        Ok(())
    }
    
    /// Cleans up resources after attack execution.
    /// 
    /// This method is called after attack execution completes and allows
    /// implementations to perform cleanup operations, release resources,
    /// or finalize state.
    /// 
    /// # Returns
    /// 
    /// * `Ok(())` - Cleanup completed successfully  
    /// * `Err(error)` - Cleanup failed
    fn cleanup(&mut self) -> Result<()> {
        Ok(())
    }
    
    /// Returns a human-readable description of the attack target.
    /// 
    /// This method provides a string representation of the target system
    /// or endpoint being attacked, useful for logging and debugging.
    /// 
    /// # Returns
    /// 
    /// A string describing the attack target
    /// 
    /// # Examples
    /// 
    /// ```rust,norun
    /// use hurtbreak_core::attack::Attack;
    /// 
    /// struct NetworkAttack { host: String, port: u16 }
    /// 
    /// impl Attack for NetworkAttack {
    ///     type Response = Vec<u8>;
    ///     // ... other required methods
    /// #     fn send_payload(&self, _: &[u8]) -> hurtbreak_core::attack::AttackResult<()> { unimplemented!() }
    /// #     fn wait_for_response(&self, _: std::time::Duration) -> hurtbreak_core::attack::AttackResult<Vec<u8>> { unimplemented!() }
    /// #     fn validate_response(&self, _: &Vec<u8>) -> hurtbreak_core::attack::AttackResult<()> { unimplemented!() }
    /// 
    ///     fn get_target_info(&self) -> String {
    ///         format!("{}:{}", self.host, self.port)
    ///     }
    /// }
    /// ```
    fn get_target_info(&self) -> String {
        "Generic Attack Target".to_string()
    }
}

/// Asynchronous version of the `Attack` trait for non-blocking attack execution.
/// 
/// This trait provides the same functionality as `Attack` but with asynchronous
/// methods that allow for concurrent execution and non-blocking I/O operations.
/// All methods return futures that can be awaited.
/// 
/// # Associated Types
/// 
/// * `Response` - The type of response expected from the target system (must implement `Send`)
/// 
/// # Examples
/// 
/// ```rust,norun
/// use hurtbreak_core::attack::{AsyncAttack, AttackResult};
/// use std::time::Duration;
/// use anyhow::anyhow;
/// use async_trait::async_trait;
/// 
/// struct AsyncNetworkAttack {
///     target: String,
/// }
/// 
/// #[async_trait]
/// impl AsyncAttack for AsyncNetworkAttack {
///     type Response = Vec<u8>;
/// 
///     async fn send_payload(&self, payload: &[u8]) -> AttackResult<()> {
///         if payload.is_empty() {
///             AttackResult::Continue(anyhow!("Empty payload"))
///         } else {
///             // Simulate async network send
///             tokio::time::sleep(Duration::from_millis(10)).await;
///             AttackResult::Ok(())
///         }
///     }
/// 
///     async fn wait_for_response(&self, timeout: Duration) -> AttackResult<Self::Response> {
///         tokio::time::sleep(timeout).await;
///         AttackResult::Ok(vec![0x52, 0x45, 0x53, 0x50])
///     }
/// 
///     async fn validate_response(&self, response: &Self::Response) -> AttackResult<()> {
///         if response.len() > 0 {
///             AttackResult::Ok(())
///         } else {
///             AttackResult::Continue(anyhow!("Empty response"))
///         }
///     }
/// }
/// ```
#[cfg(feature = "async")]
#[async_trait]
pub trait AsyncAttack {
    /// The type of response expected from the attack target (must be `Send` for async).
    type Response: Send;
    
    /// Asynchronously sends a payload to the target system.
    /// 
    /// This method transmits the attack payload to the target and returns
    /// a future that resolves to an `AttackResult` indicating the transmission status.
    /// 
    /// # Arguments
    /// 
    /// * `payload` - The byte array containing the attack payload to send
    /// 
    /// # Returns
    /// 
    /// A future that resolves to:
    /// * `Ok(())` - Payload sent successfully
    /// * `Continue(error)` - Payload send failed, but attack should continue
    /// * `Stop(error)` - Payload send failed, attack should be aborted
    async fn send_payload(&self, payload: &[u8]) -> AttackResult<()>;
    
    /// Asynchronously waits for a response from the target system.
    /// 
    /// This method returns a future that waits for a response from the target
    /// system for up to the specified timeout duration.
    /// 
    /// # Arguments
    /// 
    /// * `timeout` - Maximum duration to wait for a response
    /// 
    /// # Returns
    /// 
    /// A future that resolves to:
    /// * `Ok(response)` - Response received successfully
    /// * `Continue(error)` - No response or invalid response, should retry
    /// * `Stop(error)` - Fatal error occurred, should abort
    async fn wait_for_response(&self, timeout: Duration) -> AttackResult<Self::Response>;
    
    /// Asynchronously validates the response received from the target system.
    /// 
    /// This method returns a future that analyzes the response to determine
    /// if it indicates a successful attack, a failure that should be retried,
    /// or a fatal condition that should stop the attack.
    /// 
    /// # Arguments
    /// 
    /// * `response` - The response data to validate
    /// 
    /// # Returns
    /// 
    /// A future that resolves to:
    /// * `Ok(())` - Response validation successful, attack succeeded
    /// * `Continue(error)` - Response invalid but should retry
    /// * `Stop(error)` - Response indicates fatal error, should abort
    async fn validate_response(&self, response: &Self::Response) -> AttackResult<()>;
    
    /// Asynchronously executes a complete attack sequence with the given payload.
    /// 
    /// This method orchestrates the full async attack flow: sending the payload,
    /// waiting for a response, and validating the result. The default
    /// implementation coordinates the other trait methods automatically.
    /// 
    /// # Arguments
    /// 
    /// * `payload` - The attack payload bytes to send
    /// 
    /// # Returns
    /// 
    /// A future that resolves to:
    /// * `Ok(response)` - Attack completed successfully with response
    /// * `Continue(error)` - Attack failed but should be retried
    /// * `Stop(error)` - Attack failed and should not be retried
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
    
    /// Asynchronously validates an attack payload before sending.
    /// 
    /// This method performs pre-transmission validation of the payload
    /// to ensure it meets basic requirements and is suitable for the
    /// specific async attack implementation.
    /// 
    /// # Arguments
    /// 
    /// * `payload` - The payload bytes to validate
    /// 
    /// # Returns
    /// 
    /// A future that resolves to:
    /// * `Ok(())` - Payload is valid and ready to send
    /// * `Err(error)` - Payload validation failed
    async fn validate_payload(&self, payload: &[u8]) -> anyhow::Result<()> {
        if payload.is_empty() {
            anyhow::bail!("Payload cannot be empty");
        }
        Ok(())
    }
    
    /// Asynchronously prepares the attack implementation for execution.
    /// 
    /// This method is called before attack execution begins and allows
    /// implementations to perform any necessary asynchronous initialization,
    /// resource allocation, or setup operations.
    /// 
    /// # Returns
    /// 
    /// A future that resolves to:
    /// * `Ok(())` - Preparation completed successfully
    /// * `Err(error)` - Preparation failed
    async fn prepare(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
    
    /// Asynchronously cleans up resources after attack execution.
    /// 
    /// This method is called after attack execution completes and allows
    /// implementations to perform asynchronous cleanup operations, release
    /// resources, or finalize state.
    /// 
    /// # Returns
    /// 
    /// A future that resolves to:
    /// * `Ok(())` - Cleanup completed successfully  
    /// * `Err(error)` - Cleanup failed
    async fn cleanup(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
    
    /// Returns a human-readable description of the async attack target.
    /// 
    /// This method provides a string representation of the target system
    /// or endpoint being attacked, useful for logging and debugging in
    /// asynchronous contexts.
    /// 
    /// # Returns
    /// 
    /// A string describing the attack target
    /// 
    /// # Examples
    /// 
    /// ```rust,norun
    /// use hurtbreak_core::attack::AsyncAttack;
    /// use async_trait::async_trait;
    /// 
    /// struct AsyncNetworkAttack { 
    ///     host: String, 
    ///     port: u16 
    /// }
    /// 
    /// #[async_trait]
    /// impl AsyncAttack for AsyncNetworkAttack {
    ///     type Response = Vec<u8>;
    ///     // ... other required methods
    /// #     async fn send_payload(&self, _: &[u8]) -> hurtbreak_core::attack::AttackResult<()> { unimplemented!() }
    /// #     async fn wait_for_response(&self, _: std::time::Duration) -> hurtbreak_core::attack::AttackResult<Vec<u8>> { unimplemented!() }
    /// #     async fn validate_response(&self, _: &Vec<u8>) -> hurtbreak_core::attack::AttackResult<()> { unimplemented!() }
    /// 
    ///     fn get_target_info(&self) -> String {
    ///         format!("ASYNC {}:{}", self.host, self.port)
    ///     }
    /// }
    /// ```
    fn get_target_info(&self) -> String {
        "Generic Async Attack Target".to_string()
    }
}