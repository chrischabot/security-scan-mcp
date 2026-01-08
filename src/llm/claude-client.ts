/**
 * Claude API Client for CVE Analysis
 */

import Anthropic from '@anthropic-ai/sdk';

let client: Anthropic | null = null;

function getClient(): Anthropic {
    if (!client) {
        const apiKey = process.env.ANTHROPIC_API_KEY;
        if (!apiKey) {
            throw new Error('ANTHROPIC_API_KEY environment variable required');
        }
        client = new Anthropic({ apiKey });
    }
    return client;
}

export async function callClaude(prompt: string, systemPrompt?: string): Promise<string> {
    const anthropic = getClient();

    const message = await anthropic.messages.create({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 8192,
        temperature: 0.3,
        system: systemPrompt,
        messages: [{ role: 'user', content: prompt }]
    });

    const textBlock = message.content.find(block => block.type === 'text');
    if (!textBlock || textBlock.type !== 'text') {
        throw new Error('No text response from Claude');
    }
    return textBlock.text;
}

export async function callClaudeJSON<T>(prompt: string, systemPrompt?: string): Promise<T> {
    const response = await callClaude(prompt, systemPrompt);

    // Extract JSON from response
    const jsonMatch = response.match(/```(?:json)?\s*([\s\S]*?)```/);
    const jsonStr = jsonMatch ? jsonMatch[1].trim() : response;

    try {
        return JSON.parse(jsonStr) as T;
    } catch {
        const objectMatch = response.match(/\{[\s\S]*\}/);
        if (objectMatch) {
            return JSON.parse(objectMatch[0]) as T;
        }
        throw new Error(`Failed to parse JSON from response`);
    }
}

export function isConfigured(): boolean {
    return !!process.env.ANTHROPIC_API_KEY;
}
