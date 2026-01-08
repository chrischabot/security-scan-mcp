/**
 * Enhanced Secrets Detection Patterns
 *
 * Combines:
 * 1. High-entropy string detection
 * 2. Specific API key regex patterns
 * 3. Common credential patterns
 *
 * Based on patterns from:
 * - secrets-patterns-db
 * - gitleaks
 * - trufflehog
 */

import { SecurityPattern } from './pattern-library.js';

/**
 * Calculate Shannon entropy of a string
 * Higher entropy = more random = more likely to be a secret
 */
export function calculateEntropy(str: string): number {
    if (!str || str.length === 0) return 0;

    const charCounts = new Map<string, number>();
    for (const char of str) {
        charCounts.set(char, (charCounts.get(char) || 0) + 1);
    }

    let entropy = 0;
    const len = str.length;

    for (const count of charCounts.values()) {
        const probability = count / len;
        entropy -= probability * Math.log2(probability);
    }

    return entropy;
}

/**
 * Check if a string has high entropy (likely a secret)
 * Thresholds based on trufflehog defaults
 */
export function isHighEntropy(str: string, minLength = 20): boolean {
    if (str.length < minLength) return false;

    const entropy = calculateEntropy(str);

    // Different thresholds for hex vs base64
    const isHex = /^[0-9a-fA-F]+$/.test(str);
    const isBase64 = /^[A-Za-z0-9+/=]+$/.test(str);

    if (isHex) {
        return entropy > 3.0; // Hex has lower max entropy
    } else if (isBase64) {
        return entropy > 4.5;
    }

    return entropy > 4.0;
}

/**
 * Specific API Key patterns with high confidence
 * These have known prefixes or formats
 */
export const API_KEY_PATTERNS: SecurityPattern[] = [
    // AWS
    {
        id: 'aws-access-key-id',
        name: 'AWS Access Key ID',
        description: 'AWS Access Key ID detected',
        cweId: 798,
        severity: 'CRITICAL',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript', 'python', 'go', 'rust', 'tsx'],
        patternType: 'regex',
        regexPattern: '(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
        message: 'AWS Access Key ID detected. This key can be used to access AWS services.',
        remediation: 'Remove the key from source code. Use environment variables or AWS IAM roles instead. Rotate the exposed key immediately.',
        references: ['https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html'],
        tags: ['aws', 'cloud', 'credentials', 'high-confidence']
    },
    {
        id: 'aws-secret-access-key',
        name: 'AWS Secret Access Key',
        description: 'AWS Secret Access Key detected (40 character base64)',
        cweId: 798,
        severity: 'CRITICAL',
        confidence: 'MEDIUM',
        languages: ['javascript', 'typescript', 'python', 'go', 'rust', 'tsx'],
        patternType: 'regex',
        regexPattern: '(?:aws_secret_access_key|aws_secret_key|secret_access_key)\\s*[=:]\\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
        message: 'Potential AWS Secret Access Key detected.',
        remediation: 'Remove the key from source code. Use environment variables or AWS Secrets Manager. Rotate the exposed key immediately.',
        references: ['https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html'],
        tags: ['aws', 'cloud', 'credentials']
    },

    // GitHub
    {
        id: 'github-pat',
        name: 'GitHub Personal Access Token',
        description: 'GitHub Personal Access Token (classic or fine-grained)',
        cweId: 798,
        severity: 'CRITICAL',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript', 'python', 'go', 'rust', 'tsx'],
        patternType: 'regex',
        regexPattern: 'gh[pousr]_[A-Za-z0-9_]{36,}',
        message: 'GitHub Personal Access Token detected. This token can access GitHub APIs.',
        remediation: 'Remove the token from source code. Use environment variables or GitHub Actions secrets. Revoke and regenerate the token.',
        references: ['https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens'],
        tags: ['github', 'token', 'high-confidence']
    },
    {
        id: 'github-oauth',
        name: 'GitHub OAuth Access Token',
        description: 'GitHub OAuth Access Token',
        cweId: 798,
        severity: 'CRITICAL',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript', 'python', 'go', 'rust', 'tsx'],
        patternType: 'regex',
        regexPattern: 'gho_[A-Za-z0-9_]{36,}',
        message: 'GitHub OAuth Access Token detected.',
        remediation: 'Remove the token from source code. OAuth tokens should be obtained at runtime and stored securely.',
        references: ['https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps'],
        tags: ['github', 'oauth', 'high-confidence']
    },

    // Stripe
    {
        id: 'stripe-secret-key',
        name: 'Stripe Secret API Key',
        description: 'Stripe Secret API Key (live or test)',
        cweId: 798,
        severity: 'CRITICAL',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript', 'python', 'go', 'rust', 'tsx'],
        patternType: 'regex',
        regexPattern: 'sk_(live|test)_[0-9a-zA-Z]{24,}',
        message: 'Stripe Secret API Key detected. This key can be used to access Stripe payment APIs.',
        remediation: 'Remove the key from source code. Use environment variables. Roll the API key in Stripe dashboard.',
        references: ['https://stripe.com/docs/keys'],
        tags: ['stripe', 'payment', 'high-confidence']
    },
    {
        id: 'stripe-restricted-key',
        name: 'Stripe Restricted API Key',
        description: 'Stripe Restricted API Key',
        cweId: 798,
        severity: 'HIGH',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript', 'python', 'go', 'rust', 'tsx'],
        patternType: 'regex',
        regexPattern: 'rk_(live|test)_[0-9a-zA-Z]{24,}',
        message: 'Stripe Restricted API Key detected.',
        remediation: 'Remove the key from source code. Use environment variables.',
        references: ['https://stripe.com/docs/keys#limit-access'],
        tags: ['stripe', 'payment', 'high-confidence']
    },

    // Slack
    {
        id: 'slack-bot-token',
        name: 'Slack Bot Token',
        description: 'Slack Bot User OAuth Token',
        cweId: 798,
        severity: 'HIGH',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript', 'python', 'go', 'rust', 'tsx'],
        patternType: 'regex',
        regexPattern: 'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}',
        message: 'Slack Bot Token detected. This token can be used to send messages as a bot.',
        remediation: 'Remove the token from source code. Use environment variables. Regenerate the token in Slack.',
        references: ['https://api.slack.com/authentication/token-types'],
        tags: ['slack', 'chat', 'high-confidence']
    },
    {
        id: 'slack-user-token',
        name: 'Slack User Token',
        description: 'Slack User OAuth Token',
        cweId: 798,
        severity: 'CRITICAL',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript', 'python', 'go', 'rust', 'tsx'],
        patternType: 'regex',
        regexPattern: 'xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}',
        message: 'Slack User Token detected. This token has user-level permissions.',
        remediation: 'Remove the token from source code. User tokens should never be committed.',
        references: ['https://api.slack.com/authentication/token-types'],
        tags: ['slack', 'chat', 'high-confidence']
    },
    {
        id: 'slack-webhook',
        name: 'Slack Webhook URL',
        description: 'Slack Incoming Webhook URL',
        cweId: 798,
        severity: 'MEDIUM',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript', 'python', 'go', 'rust', 'tsx'],
        patternType: 'regex',
        regexPattern: 'https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+',
        message: 'Slack Webhook URL detected. This URL can be used to post messages to a channel.',
        remediation: 'Remove the URL from source code. Use environment variables.',
        references: ['https://api.slack.com/messaging/webhooks'],
        tags: ['slack', 'webhook']
    },

    // Google Cloud
    {
        id: 'gcp-api-key',
        name: 'Google Cloud API Key',
        description: 'Google Cloud Platform API Key',
        cweId: 798,
        severity: 'HIGH',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript', 'python', 'go', 'rust', 'tsx'],
        patternType: 'regex',
        regexPattern: 'AIza[0-9A-Za-z_-]{35}',
        message: 'Google Cloud API Key detected.',
        remediation: 'Remove the key from source code. Use environment variables or service accounts.',
        references: ['https://cloud.google.com/docs/authentication/api-keys'],
        tags: ['google', 'cloud', 'high-confidence']
    },
    {
        id: 'gcp-service-account',
        name: 'Google Cloud Service Account',
        description: 'Google Cloud service account JSON key file content',
        cweId: 798,
        severity: 'CRITICAL',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript', 'python', 'go', 'rust', 'tsx'],
        patternType: 'regex',
        regexPattern: '"type"\\s*:\\s*"service_account"',
        message: 'Google Cloud service account credentials detected.',
        remediation: 'Remove service account JSON from source code. Use workload identity or environment-based authentication.',
        references: ['https://cloud.google.com/iam/docs/service-account-overview'],
        tags: ['google', 'cloud', 'service-account']
    },

    // Private Keys
    {
        id: 'private-key-rsa',
        name: 'RSA Private Key',
        description: 'RSA Private Key in PEM format',
        cweId: 798,
        severity: 'CRITICAL',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript', 'python', 'go', 'rust', 'tsx'],
        patternType: 'regex',
        regexPattern: '-----BEGIN RSA PRIVATE KEY-----',
        message: 'RSA Private Key detected. Private keys should never be committed to source control.',
        remediation: 'Remove the private key from source code. Use a secrets manager or certificate management system.',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html'],
        tags: ['private-key', 'crypto', 'high-confidence']
    },
    {
        id: 'private-key-generic',
        name: 'Private Key',
        description: 'Generic Private Key in PEM format',
        cweId: 798,
        severity: 'CRITICAL',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript', 'python', 'go', 'rust', 'tsx'],
        patternType: 'regex',
        regexPattern: '-----BEGIN ((EC|PGP|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY( BLOCK)?-----',
        message: 'Private Key detected. Private keys should never be committed to source control.',
        remediation: 'Remove the private key from source code. Use a secrets manager.',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html'],
        tags: ['private-key', 'crypto', 'high-confidence']
    },

    // OpenAI / Anthropic
    {
        id: 'openai-api-key',
        name: 'OpenAI API Key',
        description: 'OpenAI API Key',
        cweId: 798,
        severity: 'HIGH',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript', 'python', 'go', 'rust', 'tsx'],
        patternType: 'regex',
        regexPattern: 'sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}',
        message: 'OpenAI API Key detected.',
        remediation: 'Remove the key from source code. Use environment variables. Regenerate the API key.',
        references: ['https://platform.openai.com/docs/api-reference/authentication'],
        tags: ['openai', 'ai', 'high-confidence']
    },
    {
        id: 'anthropic-api-key',
        name: 'Anthropic API Key',
        description: 'Anthropic Claude API Key',
        cweId: 798,
        severity: 'HIGH',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript', 'python', 'go', 'rust', 'tsx'],
        patternType: 'regex',
        regexPattern: 'sk-ant-api[a-zA-Z0-9_-]{32,}',
        message: 'Anthropic API Key detected.',
        remediation: 'Remove the key from source code. Use environment variables.',
        references: ['https://docs.anthropic.com/en/api/getting-started'],
        tags: ['anthropic', 'ai', 'high-confidence']
    },

    // Database Connection Strings
    {
        id: 'postgres-connection-string',
        name: 'PostgreSQL Connection String',
        description: 'PostgreSQL connection string with credentials',
        cweId: 798,
        severity: 'CRITICAL',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript', 'python', 'go', 'rust', 'tsx'],
        patternType: 'regex',
        regexPattern: 'postgres(ql)?://[^:]+:[^@]+@[^/]+/[^\\s"\']+',
        message: 'PostgreSQL connection string with embedded credentials detected.',
        remediation: 'Use environment variables for database credentials. Never embed passwords in connection strings.',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html'],
        tags: ['database', 'postgres', 'connection-string']
    },
    {
        id: 'mongodb-connection-string',
        name: 'MongoDB Connection String',
        description: 'MongoDB connection string with credentials',
        cweId: 798,
        severity: 'CRITICAL',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript', 'python', 'go', 'rust', 'tsx'],
        patternType: 'regex',
        regexPattern: 'mongodb(\\+srv)?://[^:]+:[^@]+@[^/]+',
        message: 'MongoDB connection string with embedded credentials detected.',
        remediation: 'Use environment variables for database credentials.',
        references: ['https://www.mongodb.com/docs/manual/reference/connection-string/'],
        tags: ['database', 'mongodb', 'connection-string']
    },

    // NPM
    {
        id: 'npm-token',
        name: 'NPM Access Token',
        description: 'NPM authentication token',
        cweId: 798,
        severity: 'HIGH',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript', 'python', 'go', 'rust', 'tsx'],
        patternType: 'regex',
        regexPattern: 'npm_[A-Za-z0-9]{36}',
        message: 'NPM access token detected. This token can be used to publish packages.',
        remediation: 'Remove the token from source code. Regenerate the token on npmjs.com.',
        references: ['https://docs.npmjs.com/about-access-tokens'],
        tags: ['npm', 'package-manager', 'high-confidence']
    },

    // Discord
    {
        id: 'discord-bot-token',
        name: 'Discord Bot Token',
        description: 'Discord Bot authentication token',
        cweId: 798,
        severity: 'HIGH',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript', 'python', 'go', 'rust', 'tsx'],
        patternType: 'regex',
        regexPattern: '[MN][A-Za-z\\d]{23,}\\.[\\w-]{6}\\.[\\w-]{27}',
        message: 'Discord Bot Token detected.',
        remediation: 'Remove the token from source code. Regenerate the token in Discord Developer Portal.',
        references: ['https://discord.com/developers/docs/topics/oauth2'],
        tags: ['discord', 'bot', 'high-confidence']
    },

    // Twilio
    {
        id: 'twilio-api-key',
        name: 'Twilio API Key',
        description: 'Twilio API Key SID',
        cweId: 798,
        severity: 'HIGH',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript', 'python', 'go', 'rust', 'tsx'],
        patternType: 'regex',
        regexPattern: 'SK[0-9a-fA-F]{32}',
        message: 'Twilio API Key detected.',
        remediation: 'Remove the key from source code. Use environment variables.',
        references: ['https://www.twilio.com/docs/iam/keys/api-key'],
        tags: ['twilio', 'sms', 'high-confidence']
    },

    // Sendgrid
    {
        id: 'sendgrid-api-key',
        name: 'SendGrid API Key',
        description: 'SendGrid API Key',
        cweId: 798,
        severity: 'HIGH',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript', 'python', 'go', 'rust', 'tsx'],
        patternType: 'regex',
        regexPattern: 'SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}',
        message: 'SendGrid API Key detected.',
        remediation: 'Remove the key from source code. Use environment variables.',
        references: ['https://docs.sendgrid.com/ui/account-and-settings/api-keys'],
        tags: ['sendgrid', 'email', 'high-confidence']
    },

    // Mailchimp
    {
        id: 'mailchimp-api-key',
        name: 'Mailchimp API Key',
        description: 'Mailchimp API Key',
        cweId: 798,
        severity: 'HIGH',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript', 'python', 'go', 'rust', 'tsx'],
        patternType: 'regex',
        regexPattern: '[0-9a-f]{32}-us[0-9]{1,2}',
        message: 'Mailchimp API Key detected.',
        remediation: 'Remove the key from source code. Use environment variables.',
        references: ['https://mailchimp.com/developer/marketing/guides/quick-start/'],
        tags: ['mailchimp', 'email', 'high-confidence']
    },

    // Firebase
    {
        id: 'firebase-url',
        name: 'Firebase Database URL',
        description: 'Firebase Realtime Database URL',
        cweId: 798,
        severity: 'MEDIUM',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript', 'python', 'go', 'rust', 'tsx'],
        patternType: 'regex',
        regexPattern: 'https://[a-z0-9-]+\\.firebaseio\\.com',
        message: 'Firebase Database URL detected. Ensure database rules are properly configured.',
        remediation: 'Review Firebase security rules. Do not rely on URL obscurity for security.',
        references: ['https://firebase.google.com/docs/database/security'],
        tags: ['firebase', 'google', 'database']
    },

    // JWT (generic but useful)
    {
        id: 'jwt-token',
        name: 'JSON Web Token',
        description: 'JSON Web Token (JWT) detected',
        cweId: 798,
        severity: 'MEDIUM',
        confidence: 'MEDIUM',
        languages: ['javascript', 'typescript', 'python', 'go', 'rust', 'tsx'],
        patternType: 'regex',
        regexPattern: 'eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}',
        message: 'JWT token detected. JWTs may contain sensitive claims.',
        remediation: 'Do not hardcode JWTs. They should be obtained at runtime and stored securely.',
        references: ['https://jwt.io/introduction'],
        tags: ['jwt', 'token']
    }
];

/**
 * Get all secrets detection patterns including the original generic pattern
 */
export function getAllSecretsPatterns(): SecurityPattern[] {
    return API_KEY_PATTERNS;
}

/**
 * Find high-entropy strings in content that might be secrets
 */
export interface EntropyMatch {
    value: string;
    entropy: number;
    startIndex: number;
    endIndex: number;
    line: number;
    column: number;
}

export function findHighEntropyStrings(
    content: string,
    minLength = 20,
    _maxLength = 200
): EntropyMatch[] {
    const matches: EntropyMatch[] = [];

    // Match quoted strings (using minLength dynamically via isHighEntropy check)
    const stringPattern = /["'`]([^"'`\n]{20,200})["'`]/g;
    let match;

    while ((match = stringPattern.exec(content)) !== null) {
        const value = match[1];

        // Skip if it looks like a path, URL without credentials, or common pattern
        if (
            value.startsWith('/') ||
            value.startsWith('./') ||
            value.startsWith('http://') ||
            value.startsWith('https://') && !value.includes('@') ||
            value.includes(' ') ||
            /^[a-z_]+$/i.test(value) // All letters/underscores (variable names)
        ) {
            continue;
        }

        const entropy = calculateEntropy(value);

        // Check if high entropy
        if (isHighEntropy(value, minLength)) {
            const beforeMatch = content.substring(0, match.index);
            const lines = beforeMatch.split('\n');
            const line = lines.length;
            const column = lines[lines.length - 1].length + 1;

            matches.push({
                value,
                entropy,
                startIndex: match.index,
                endIndex: match.index + match[0].length,
                line,
                column
            });
        }
    }

    return matches;
}
