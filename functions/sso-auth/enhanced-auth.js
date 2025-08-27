/**
 * Enhanced Authentication Module for Universal SSO
 * Provides improved security, performance, and reliability
 */

const crypto = require('crypto');

class EnhancedAuthManager {
    constructor(config = {}) {
        this.config = {
            tokenExpiry: config.tokenExpiry || 3600,
            refreshTokenExpiry: config.refreshTokenExpiry || 2592000,
            maxLoginAttempts: config.maxLoginAttempts || 5,
            lockoutDuration: config.lockoutDuration || 900000,
            enableMFA: config.enableMFA !== false,
            enableRateLimiting: config.enableRateLimiting !== false,
            sessionTimeout: config.sessionTimeout || 1800000,
            ...config
        };

        this.sessions = new Map();
        this.loginAttempts = new Map();
        this.rateLimits = new Map();
        this.mfaTokens = new Map();
    }

    /**
     * Authenticate user with enhanced security
     */
    async authenticate(credentials, options = {}) {
        const { provider, email, password, token } = credentials;

        // Check rate limiting
        if (this.config.enableRateLimiting && !this.checkRateLimit(email)) {
            throw new Error('Rate limit exceeded. Please try again later.');
        }

        // Check login attempts
        if (!this.checkLoginAttempts(email)) {
            throw new Error('Account locked due to multiple failed attempts.');
        }

        try {
            let user;
            
            // Provider-specific authentication
            switch (provider) {
                case 'google':
                    user = await this.authenticateGoogle(token);
                    break;
                case 'github':
                    user = await this.authenticateGithub(token);
                    break;
                case 'microsoft':
                    user = await this.authenticateMicrosoft(token);
                    break;
                case 'email':
                default:
                    user = await this.authenticateEmail(email, password);
                    break;
            }

            // Check if MFA is required
            if (this.config.enableMFA && user.mfaEnabled) {
                const mfaToken = this.generateMFAToken(user.id);
                this.mfaTokens.set(mfaToken, {
                    userId: user.id,
                    expires: Date.now() + 300000 // 5 minutes
                });
                
                return {
                    requiresMFA: true,
                    mfaToken,
                    mfaMethods: user.mfaMethods || ['totp', 'sms']
                };
            }

            // Create session
            const session = await this.createSession(user);
            
            // Reset login attempts on success
            this.loginAttempts.delete(email);
            
            return {
                success: true,
                session,
                user: this.sanitizeUser(user)
            };

        } catch (error) {
            // Track failed attempts
            this.recordFailedAttempt(email);
            throw error;
        }
    }

    /**
     * Verify MFA code
     */
    async verifyMFA(mfaToken, code, method = 'totp') {
        const tokenData = this.mfaTokens.get(mfaToken);
        
        if (!tokenData || tokenData.expires < Date.now()) {
            throw new Error('Invalid or expired MFA token');
        }

        const verified = await this.verifyMFACode(tokenData.userId, code, method);
        
        if (!verified) {
            throw new Error('Invalid MFA code');
        }

        // Get user and create session
        const user = await this.getUser(tokenData.userId);
        const session = await this.createSession(user);
        
        // Clean up MFA token
        this.mfaTokens.delete(mfaToken);
        
        return {
            success: true,
            session,
            user: this.sanitizeUser(user)
        };
    }

    /**
     * Create secure session
     */
    async createSession(user) {
        const sessionId = this.generateSessionId();
        const accessToken = this.generateAccessToken(user);
        const refreshToken = this.generateRefreshToken();
        
        const session = {
            id: sessionId,
            userId: user.id,
            accessToken,
            refreshToken,
            createdAt: Date.now(),
            expiresAt: Date.now() + (this.config.tokenExpiry * 1000),
            refreshExpiresAt: Date.now() + (this.config.refreshTokenExpiry * 1000),
            userAgent: null,
            ipAddress: null
        };

        this.sessions.set(sessionId, session);
        
        // Set session timeout
        setTimeout(() => {
            this.invalidateSession(sessionId);
        }, this.config.sessionTimeout);

        return {
            sessionId,
            accessToken,
            refreshToken,
            expiresIn: this.config.tokenExpiry
        };
    }

    /**
     * Refresh session
     */
    async refreshSession(refreshToken) {
        // Find session with matching refresh token
        let session;
        for (const [id, s] of this.sessions.entries()) {
            if (s.refreshToken === refreshToken && s.refreshExpiresAt > Date.now()) {
                session = s;
                break;
            }
        }

        if (!session) {
            throw new Error('Invalid or expired refresh token');
        }

        // Get user
        const user = await this.getUser(session.userId);
        
        // Generate new tokens
        const newAccessToken = this.generateAccessToken(user);
        const newRefreshToken = this.generateRefreshToken();
        
        // Update session
        session.accessToken = newAccessToken;
        session.refreshToken = newRefreshToken;
        session.expiresAt = Date.now() + (this.config.tokenExpiry * 1000);
        session.refreshExpiresAt = Date.now() + (this.config.refreshTokenExpiry * 1000);

        return {
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
            expiresIn: this.config.tokenExpiry
        };
    }

    /**
     * Validate session
     */
    async validateSession(sessionId, accessToken) {
        const session = this.sessions.get(sessionId);
        
        if (!session) {
            return { valid: false, reason: 'Session not found' };
        }

        if (session.accessToken !== accessToken) {
            return { valid: false, reason: 'Invalid access token' };
        }

        if (session.expiresAt < Date.now()) {
            return { valid: false, reason: 'Session expired' };
        }

        return {
            valid: true,
            userId: session.userId,
            expiresIn: Math.floor((session.expiresAt - Date.now()) / 1000)
        };
    }

    /**
     * Invalidate session
     */
    invalidateSession(sessionId) {
        this.sessions.delete(sessionId);
    }

    /**
     * Check rate limiting
     */
    checkRateLimit(identifier) {
        const now = Date.now();
        const limit = this.rateLimits.get(identifier) || { count: 0, resetAt: now + 60000 };

        if (limit.resetAt < now) {
            limit.count = 1;
            limit.resetAt = now + 60000;
        } else {
            limit.count++;
        }

        this.rateLimits.set(identifier, limit);
        
        return limit.count <= 10; // Max 10 attempts per minute
    }

    /**
     * Check login attempts
     */
    checkLoginAttempts(identifier) {
        const attempts = this.loginAttempts.get(identifier);
        
        if (!attempts) {
            return true;
        }

        if (attempts.lockedUntil && attempts.lockedUntil > Date.now()) {
            return false;
        }

        return attempts.count < this.config.maxLoginAttempts;
    }

    /**
     * Record failed attempt
     */
    recordFailedAttempt(identifier) {
        const attempts = this.loginAttempts.get(identifier) || { count: 0 };
        attempts.count++;
        
        if (attempts.count >= this.config.maxLoginAttempts) {
            attempts.lockedUntil = Date.now() + this.config.lockoutDuration;
        }
        
        this.loginAttempts.set(identifier, attempts);
    }

    /**
     * Generate session ID
     */
    generateSessionId() {
        return crypto.randomBytes(32).toString('hex');
    }

    /**
     * Generate access token
     */
    generateAccessToken(user) {
        const header = Buffer.from(JSON.stringify({
            alg: 'HS256',
            typ: 'JWT'
        })).toString('base64url');

        const payload = Buffer.from(JSON.stringify({
            sub: user.id,
            email: user.email,
            roles: user.roles || [],
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + this.config.tokenExpiry
        })).toString('base64url');

        const signature = crypto
            .createHmac('sha256', this.config.jwtSecret || 'secret')
            .update(`${header}.${payload}`)
            .digest('base64url');

        return `${header}.${payload}.${signature}`;
    }

    /**
     * Generate refresh token
     */
    generateRefreshToken() {
        return crypto.randomBytes(64).toString('hex');
    }

    /**
     * Generate MFA token
     */
    generateMFAToken(userId) {
        return crypto
            .createHash('sha256')
            .update(`${userId}:${Date.now()}:${Math.random()}`)
            .digest('hex');
    }

    /**
     * Verify MFA code
     */
    async verifyMFACode(userId, code, method) {
        // Implementation would depend on the MFA method
        // This is a placeholder
        return true;
    }

    /**
     * Provider-specific authentication methods
     */
    async authenticateGoogle(token) {
        // Implement Google OAuth validation
        return { id: 'google-user', email: 'user@gmail.com' };
    }

    async authenticateGithub(token) {
        // Implement GitHub OAuth validation
        return { id: 'github-user', email: 'user@github.com' };
    }

    async authenticateMicrosoft(token) {
        // Implement Microsoft OAuth validation
        return { id: 'ms-user', email: 'user@outlook.com' };
    }

    async authenticateEmail(email, password) {
        // Implement email/password validation
        return { id: 'email-user', email };
    }

    /**
     * Get user by ID
     */
    async getUser(userId) {
        // Placeholder - would fetch from database
        return { id: userId, email: 'user@example.com' };
    }

    /**
     * Sanitize user data for client
     */
    sanitizeUser(user) {
        const { password, ...sanitized } = user;
        return sanitized;
    }

    /**
     * Clean up expired sessions
     */
    cleanupSessions() {
        const now = Date.now();
        
        for (const [id, session] of this.sessions.entries()) {
            if (session.refreshExpiresAt < now) {
                this.sessions.delete(id);
            }
        }
    }

    /**
     * Get statistics
     */
    getStatistics() {
        return {
            activeSessions: this.sessions.size,
            lockedAccounts: Array.from(this.loginAttempts.values())
                .filter(a => a.lockedUntil && a.lockedUntil > Date.now()).length,
            pendingMFA: this.mfaTokens.size
        };
    }
}

module.exports = EnhancedAuthManager;