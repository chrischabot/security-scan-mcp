// Vulnerable React/TypeScript component for testing the scanner

import React, { useState, useEffect } from 'react';
import axios from 'axios';

interface User {
    id: number;
    name: string;
    bio: string;
}

// CWE-79: XSS via dangerouslySetInnerHTML
export const UserProfile: React.FC<{ user: User }> = ({ user }) => {
    return (
        <div className="profile">
            <h1>{user.name}</h1>
            {/* VULNERABLE: XSS via dangerouslySetInnerHTML */}
            <div dangerouslySetInnerHTML={{ __html: user.bio }} />
        </div>
    );
};

// CWE-79: XSS via innerHTML in useEffect
export const DynamicContent: React.FC<{ content: string }> = ({ content }) => {
    useEffect(() => {
        const container = document.getElementById('dynamic-content');
        if (container) {
            // VULNERABLE: XSS via innerHTML
            container.innerHTML = content;
        }
    }, [content]);

    return <div id="dynamic-content" />;
};

// CWE-89: SQL injection pattern (backend would execute this)
export const SearchComponent: React.FC = () => {
    const [query, setQuery] = useState('');

    const handleSearch = async () => {
        // This would be vulnerable if the backend uses this directly in SQL
        const response = await axios.get(`/api/search?q=${query}`);
        console.log(response.data);
    };

    return (
        <div>
            <input value={query} onChange={e => setQuery(e.target.value)} />
            <button onClick={handleSearch}>Search</button>
        </div>
    );
};

// CWE-918: SSRF pattern (user-controlled URL)
export const ImageProxy: React.FC = () => {
    const [url, setUrl] = useState('');
    const [imageData, setImageData] = useState<string | null>(null);

    const fetchImage = async () => {
        // VULNERABLE: SSRF if backend proxies without validation
        const response = await fetch(`/api/proxy?url=${encodeURIComponent(url)}`);
        const data = await response.text();
        setImageData(data);
    };

    return (
        <div>
            <input value={url} onChange={e => setUrl(e.target.value)} placeholder="Image URL" />
            <button onClick={fetchImage}>Fetch</button>
            {imageData && <img src={imageData} alt="Proxied" />}
        </div>
    );
};

// CWE-798: Hardcoded API key
const API_KEY = "sk-anthropic-key-abc123xyz789";

// CWE-94: Eval usage (dangerous)
export const Calculator: React.FC = () => {
    const [expression, setExpression] = useState('');
    const [result, setResult] = useState<number | null>(null);

    const calculate = () => {
        try {
            // VULNERABLE: Code injection via eval
            const value = eval(expression);
            setResult(value);
        } catch (e) {
            console.error('Invalid expression');
        }
    };

    return (
        <div>
            <input value={expression} onChange={e => setExpression(e.target.value)} />
            <button onClick={calculate}>Calculate</button>
            {result !== null && <p>Result: {result}</p>}
        </div>
    );
};

// CWE-94: Dynamic code execution via Function constructor
export const CodeRunner: React.FC<{ code: string }> = ({ code }) => {
    const runCode = () => {
        // VULNERABLE: Code injection via Function constructor
        const fn = new Function('context', code);
        return fn({ timestamp: Date.now() });
    };

    return (
        <div>
            <button onClick={runCode}>Run Code</button>
        </div>
    );
};

export default UserProfile;
