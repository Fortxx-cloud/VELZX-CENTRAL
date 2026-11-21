import { useState } from 'react';

const navigation = [
  {
    label: 'WORKSPACE',
    items: [
      { id: 'overview', name: 'Overview', icon: '◫' },
      { id: 'api-keys', name: 'API Keys', icon: '⌘' },
      { id: 'models', name: 'Models', icon: '◇' },
      { id: 'playground', name: 'API Playground', icon: '▷' },
    ],
  },
  {
    label: 'DEVELOPMENT',
    items: [
      { id: 'documentation', name: 'API Documentation', icon: '▤' },
      { id: 'analytics', name: 'Usage Analytics', icon: '▥' },
      { id: 'logs', name: 'Request Logs', icon: '≡' },
    ],
  },
  {
    label: 'ACCOUNT',
    items: [
      { id: 'settings', name: 'Account Settings', icon: '⚙' },
      { id: 'security', name: 'Security & Sessions', icon: '⬡' },
    ],
  },
];

const pageInfo = {
  overview: {
    title: 'Overview',
    description: 'Monitor your API workspace and development activity.',
  },
  'api-keys': {
    title: 'API Keys',
    description: 'Create and manage credentials for your applications.',
  },
  models: {
    title: 'Models',
    description: 'Explore the AI models available through Central.',
  },
  playground: {
    title: 'API Playground',
    description: 'Build and inspect API requests interactively.',
  },
  documentation: {
    title: 'API Documentation',
    description: 'Guides, references, and integration resources.',
  },
  analytics: {
    title: 'Usage Analytics',
    description: 'Understand API consumption and usage patterns.',
  },
  logs: {
    title: 'Request Logs',
    description: 'Inspect request history and response details.',
  },
  settings: {
    title: 'Account Settings',
    description: 'Manage your developer account preferences.',
  },
  security: {
    title: 'Security & Sessions',
    description: 'Review account security and active sessions.',
  },
};

const metrics = [
  { label: 'Total Requests', value: '—', detail: 'Usage data unavailable', icon: '↗' },
  { label: 'API Keys', value: '—', detail: 'Key registry unavailable', icon: '⌘' },
  { label: 'Available Models', value: '—', detail: 'Model registry unavailable', icon: '◇' },
  { label: 'Success Rate', value: '—', detail: 'No metrics connected', icon: '✓' },
];

function Sidebar({ activePage, onNavigate, mobileOpen, onClose }) {
  return (
    <>
      {mobileOpen && (
        <button
          className="mobile-overlay"
          aria-label="Close navigation"
          onClick={onClose}
        />
      )}
      <aside className={`sidebar ${mobileOpen ? 'sidebar-open' : ''}`}>
        <div className="sidebar-brand">
          <div className="brand-symbol">V</div>
          <div className="brand-copy">
            <strong>VELZX</strong>
            <span>AI CENTRAL</span>
          </div>
          <button
            className="mobile-close"
            onClick={onClose}
            aria-label="Close menu"
          >
            ×
          </button>
        </div>

        <div className="workspace-switcher">
          <div className="workspace-avatar">D</div>
          <div className="workspace-copy">
            <strong>Developer Workspace</strong>
            <span>Personal workspace</span>
          </div>
          <span className="switcher-arrow">⌄</span>
        </div>

        <nav className="side-navigation" aria-label="Main navigation">
          {navigation.map((group) => (
            <div className="nav-group" key={group.label}>
              <p className="nav-heading">{group.label}</p>
              {group.items.map((item) => (
                <button
                  key={item.id}
                  className={`nav-item ${activePage === item.id ? 'active' : ''}`}
                  onClick={() => {
                    onNavigate(item.id);
                    onClose();
                  }}
                >
                  <span className="nav-icon">{item.icon}</span>
                  <span>{item.name}</span>
                  {activePage === item.id && <span className="active-indicator" />}
                </button>
              ))}
            </div>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="help-card">
            <div className="help-icon">?</div>
            <div>
              <strong>Need assistance?</strong>
              <span>Explore developer resources.</span>
            </div>
          </div>
          <div className="sidebar-version">
            <span className="version-dot" />
            Developer Portal
            <span className="version-number">v1.0</span>
          </div>
        </div>
      </aside>
    </>
  );
}

function Header({ title, onMenuClick }) {
  return (
    <header className="topbar">
      <div className="topbar-left">
        <button
          className="menu-button"
          onClick={onMenuClick}
          aria-label="Open navigation"
        >
          ☰
        </button>
        <div className="breadcrumb">
          <span>Developer Portal</span>
          <span className="breadcrumb-divider">/</span>
          <strong>{title}</strong>
        </div>
      </div>

      <div className="topbar-right">
        <div className="environment-label">
          <span className="environment-dot" />
          Central Workspace
        </div>
        <div className="account-avatar" title="Developer account">D</div>
      </div>
    </header>
  );
}

function SectionHeading({ eyebrow, title, description, children }) {
  return (
    <div className="section-heading">
      <div>
        {eyebrow && <p className="section-eyebrow">{eyebrow}</p>}
        <h2>{title}</h2>
        <p>{description}</p>
      </div>
      {children}
    </div>
  );
}

function Overview({ onNavigate }) {
  return (
    <>
      <section className="welcome-panel">
        <div className="welcome-content">
          <div className="welcome-badge">
            <span className="welcome-badge-dot" />
            DEVELOPER WORKSPACE
          </div>
          <h2>Build with intelligence.</h2>
          <p>
            Your centralized workspace for accessing AI infrastructure,
            managing integrations, and developing with VELZX.
          </p>
          <button
            className="primary-button"
            onClick={() => onNavigate('documentation')}
          >
            Explore documentation <span>→</span>
          </button>
        </div>
        <div className="welcome-art" aria-hidden="true">
          <div className="orbit orbit-one" />
          <div className="orbit orbit-two" />
          <div className="orbit-core">V</div>
          <span className="orbit-node node-one" />
          <span className="orbit-node node-two" />
          <span className="orbit-node node-three" />
        </div>
        <div className="welcome-glow" />
      </section>

      <SectionHeading
        eyebrow="WORKSPACE SUMMARY"
        title="Your overview"
        description="A snapshot of your developer workspace."
      />

      <div className="metrics-grid">
        {metrics.map((metric) => (
          <article className="metric-card" key={metric.label}>
            <div className="metric-top">
              <span>{metric.label}</span>
              <span className="metric-icon">{metric.icon}</span>
            </div>
            <strong className="metric-value">{metric.value}</strong>
            <span className="metric-detail">{metric.detail}</span>
          </article>
        ))}
      </div>

      <div className="overview-grid">
        <section className="content-card system-card">
          <div className="card-heading">
            <div>
              <h3>Platform connectivity</h3>
              <p>Connection status for workspace services.</p>
            </div>
            <span className="subtle-label">LIVE DATA</span>
          </div>
          <div className="connection-empty">
            <div className="connection-symbol">⌁</div>
            <strong>Not connected yet</strong>
            <p>
              Platform service status will appear here when the dashboard
              is connected to the Central API.
            </p>
          </div>
        </section>

        <section className="content-card quick-card">
          <div className="card-heading">
            <div>
              <h3>Developer resources</h3>
              <p>Continue with your development workflow.</p>
            </div>
          </div>
          <button
            className="resource-link"
            onClick={() => onNavigate('documentation')}
          >
            <span className="resource-icon">▤</span>
            <span>
              <strong>API Documentation</strong>
              <small>Read integration references</small>
            </span>
            <span className="resource-arrow">→</span>
          </button>
          <button
            className="resource-link"
            onClick={() => onNavigate('playground')}
          >
            <span className="resource-icon">▷</span>
            <span>
              <strong>API Playground</strong>
              <small>Prepare API requests</small>
            </span>
            <span className="resource-arrow">→</span>
          </button>
          <button
            className="resource-link"
            onClick={() => onNavigate('api-keys')}
          >
            <span className="resource-icon">⌘</span>
            <span>
              <strong>API Keys</strong>
              <small>View credential management</small>
            </span>
            <span className="resource-arrow">→</span>
          </button>
        </section>
      </div>
    </>
  );
}


function ApiKeysPage() {
  return (
    <div className="api-keys-page">
      <section className="api-key-summary">
        <article className="api-key-stat">
          <div className="api-key-stat-top">
            <span>Total API Keys</span>
            <span className="api-key-stat-icon">⌘</span>
          </div>
          <strong>—</strong>
          <small>Key registry unavailable</small>
        </article>

        <article className="api-key-stat">
          <div className="api-key-stat-top">
            <span>Active Keys</span>
            <span className="api-key-stat-icon">✓</span>
          </div>
          <strong>—</strong>
          <small>Key status unavailable</small>
        </article>
      </section>

      <section className="api-key-list content-card">
        <div className="api-key-list-heading">
          <div>
            <h3>Your credentials</h3>
            <p>API credentials associated with your developer workspace.</p>
          </div>
          <span className="api-key-pending">REGISTRY OFFLINE</span>
        </div>

        <div className="api-key-empty">
          <div className="api-key-empty-icon">⌘</div>
          <h3>No API keys available</h3>
          <p>
            Your API credentials will appear here when API Key management
            is implemented and connected to Central.
          </p>
          <span className="api-key-empty-status">
            UI ready · Backend integration pending
          </span>
        </div>
      </section>

      <section className="api-key-security content-card">
        <div className="api-key-security-icon">⬡</div>
        <div>
          <h3>Keep your API keys secure</h3>
          <p>
            Treat API keys as confidential credentials. Never expose them
            in public repositories, frontend source code, browser storage,
            or client-side applications.
          </p>
          <p>
            Store credentials in a secure server-side environment and
            rotate them if they are suspected to be compromised.
          </p>
        </div>
      </section>
    </div>
  );
}


function ModelsPage() {
  return (
    <div className="models-page">
      <section className="models-summary">
        <article className="model-stat">
          <div className="model-stat-top">
            <span>Available Models</span>
            <span className="model-stat-icon">◇</span>
          </div>
          <strong>—</strong>
          <small>Model registry data unavailable</small>
        </article>

        <article className="model-stat">
          <div className="model-stat-top">
            <span>Model Providers</span>
            <span className="model-stat-icon">⌘</span>
          </div>
          <strong>—</strong>
          <small>Provider information unavailable</small>
        </article>

        <article className="model-stat">
          <div className="model-stat-top">
            <span>Registry Status</span>
            <span className="model-stat-icon">◎</span>
          </div>
          <strong className="model-stat-pending">PENDING</strong>
          <small>Central Model Registry not connected</small>
        </article>
      </section>

      <section className="models-catalog content-card">
        <div className="models-catalog-heading">
          <div>
            <h3>Model Catalog</h3>
            <p>
              Explore model identifiers and capabilities available through
              VELZX AI Central.
            </p>
          </div>
          <span className="models-pending">INTEGRATION PENDING</span>
        </div>

        <div className="models-table-wrapper">
          <table className="models-table">
            <thead>
              <tr>
                <th>MODEL</th>
                <th>PROVIDER</th>
                <th>CONTEXT WINDOW</th>
                <th>CAPABILITIES</th>
                <th>STATUS</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td colSpan="5">
                  <div className="models-empty">
                    <div className="models-empty-icon">◇</div>
                    <h3>No models available</h3>
                    <p>
                      Model information will appear here when the Central
                      Model Registry is implemented and connected.
                    </p>
                    <span>
                      UI ready · Backend integration pending
                    </span>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="models-information">
        <article className="model-information-card">
          <span className="model-information-icon">⌘</span>
          <h3>Model identifiers</h3>
          <p>
            Model IDs and provider mappings will be supplied by the Central
            Model Registry.
          </p>
        </article>

        <article className="model-information-card">
          <span className="model-information-icon">◇</span>
          <h3>Model capabilities</h3>
          <p>
            Supported capabilities and modalities will be displayed from
            registered model metadata.
          </p>
        </article>

        <article className="model-information-card">
          <span className="model-information-icon">▤</span>
          <h3>Context window</h3>
          <p>
            Context limits and model specifications will appear when
            authoritative registry data is available.
          </p>
        </article>
      </section>
    </div>
  );
}



function DocumentationPage() {
  const authEndpoints = [
    {
      method: 'GET',
      path: '/api/v1/me',
      auth: 'Session cookie',
      description: 'Retrieves the identity and account status associated with the active session.',
      response: `{
  "status": "ok",
  "user": {
    "id": "<user-id>",
    "email": "<account-email>",
    "accountStatus": "<account-status>",
    "emailVerified": true
  }
}`,
    },
    {
      method: 'GET',
      path: '/api/v1/auth/sessions',
      auth: 'Session cookie',
      description: 'Lists active sessions belonging to the authenticated account. Session tokens and hashes are never returned.',
      response: `{
  "status": "ok",
  "sessions": [
    {
      "id": "<session-id>",
      "createdAt": "<timestamp>",
      "expiresAt": "<timestamp>",
      "current": true
    }
  ]
}`,
    },
    {
      method: 'POST',
      path: '/api/v1/auth/logout',
      auth: 'Optional session cookie',
      description: 'Revokes the current session if one exists and clears the session cookie. This operation is idempotent.',
      response: 'HTTP 204 No Content',
    },
    {
      method: 'DELETE',
      path: '/api/v1/auth/sessions/:sessionId',
      auth: 'Session cookie',
      description: 'Revokes a session belonging to the current account. If the revoked session is the current session, its cookie is also cleared.',
      response: 'HTTP 204 No Content',
    },
  ];

  const oauthProviders = ['google', 'github', 'microsoft'];

  return (
    <div className="docs-page">
      <section className="docs-intro content-card">
        <div className="docs-intro-mark">▤</div>
        <div>
          <span className="docs-eyebrow">DEVELOPER RESOURCES</span>
          <h2>VELZX Central API Reference</h2>
          <p>
            Endpoint references, authentication details, and integration guides based on
            the Central implementation currently available.
          </p>
        </div>
        <span className="docs-version">CURRENT API</span>
      </section>

      <div className="docs-layout">
        <aside className="docs-index content-card">
          <span className="docs-index-title">ON THIS PAGE</span>
          <a href="#docs-getting-started">Getting started</a>
          <a href="#docs-authentication">Authentication</a>
          <a href="#docs-auth-api">Auth API</a>
          <a href="#docs-oauth">Social login / OAuth</a>
          <a href="#docs-errors">Error responses</a>
          <a href="#docs-availability">API availability</a>
        </aside>

        <div className="docs-content">
          <section className="docs-section content-card" id="docs-getting-started">
            <span className="docs-section-kicker">01 / INTRODUCTION</span>
            <h3>Getting started</h3>
            <p>
              Use the public API origin configured for Central. All API traffic must
              pass through the configured public ingress or proxy. Do not send
              application requests directly to the internal backend origin.
            </p>
            <div className="docs-code-label">BASE URL</div>
            <pre className="docs-code"><code>{'https://<your-central-public-origin>'}</code></pre>
            <p className="docs-muted">
              Replace the placeholder with your deployment's public origin.
              It must match the application's configured origin.
            </p>
            <div className="docs-callout">
              <strong>Health check exception</strong>
              <p>
                <code>GET /health</code> does not require an ingress signature. All other Central endpoints
                undergo ingress verification before reaching their route handlers.
              </p>
            </div>
            <div className="docs-code-label">HEALTH CHECK</div>
            <pre className="docs-code"><code>{`curl --request GET "$CENTRAL_API_URL/health"`}</code></pre>
            <pre className="docs-code docs-code-secondary"><code>{`{
  "status": "ok",
  "service": "velzx-central"
}`}</code></pre>
          </section>

          <section className="docs-section content-card" id="docs-authentication">
            <span className="docs-section-kicker">02 / SECURITY</span>
            <h3>Authentication</h3>
            <p>
              Auth API menggunakan session cookie. Central tidak menggunakan
              bearer token untuk autentikasi endpoint ini.
            </p>
            <div className="docs-cookie-name">__Host-velzx_session</div>
            <div className="docs-fact-grid">
              <div><span>SECURE</span><strong>Enabled</strong></div>
              <div><span>HTTP ONLY</span><strong>Enabled</strong></div>
              <div><span>SAME SITE</span><strong>Lax</strong></div>
              <div><span>PATH</span><strong>/</strong></div>
              <div><span>DOMAIN</span><strong>Not set</strong></div>
              <div><span>SESSION MAX AGE</span><strong>7 days</strong></div>
            </div>
            <ul className="docs-list">
              <li>The browser automatically sends the session cookie according to its cookie policy.</li>
              <li>Do not read, expose, or store session tokens in frontend JavaScript.</li>
              <li>State-changing routes that use cookies require an <code>Origin</code> header that exactly matches the configured <code>APP_ORIGIN</code>.</li>
              <li>Auth responses use <code>Cache-Control: no-store</code>.</li>
            </ul>
          </section>

          <section className="docs-section content-card" id="docs-auth-api">
            <span className="docs-section-kicker">03 / ENDPOINT REFERENCE</span>
            <h3>Authentication API</h3>
            <p>
              The following endpoints are currently available in the Auth API. All paths
              use the public API origin.
            </p>
            <div className="docs-endpoint-list">
              {authEndpoints.map((endpoint) => (
                <article className="docs-endpoint" key={endpoint.method + endpoint.path}>
                  <div className="docs-endpoint-top">
                    <span className={'docs-method docs-method-' + endpoint.method.toLowerCase()}>
                      {endpoint.method}
                    </span>
                    <code>{endpoint.path}</code>
                  </div>
                  <p>{endpoint.description}</p>
                  <div className="docs-endpoint-meta">
                    <span>AUTHENTICATION</span>
                    <strong>{endpoint.auth}</strong>
                  </div>
                  <div className="docs-code-label">SUCCESS RESPONSE</div>
                  <pre className="docs-code"><code>{endpoint.response}</code></pre>
                  {endpoint.method !== 'GET' && (
                    <div className="docs-callout docs-callout-subtle">
                      <strong>Origin validation</strong>
                      <p>
                        Send an <code>Origin</code> header that exactly matches the configured
                        <code>APP_ORIGIN</code>. Requests without a valid origin are rejected.
                      </p>
                    </div>
                  )}
                </article>
              ))}
            </div>
            <div className="docs-code-label">COOKIE-AWARE CLIENT EXAMPLE</div>
            <pre className="docs-code"><code>{`# Example only: COOKIE_HEADER contains a session cookie from an authenticated flow.
curl --request GET "$CENTRAL_API_URL/api/v1/me" \\
  --cookie "$VELZX_SESSION_COOKIE"`}</code></pre>
            <p className="docs-muted">
              <code>$VELZX_SESSION_COOKIE</code> contains a session cookie value from an authenticated
              flow, for example <code>__Host-velzx_session=...</code>.
              Never put session cookies in source code or repositories.
            </p>
          </section>

          <section className="docs-section content-card" id="docs-oauth">
            <span className="docs-section-kicker">04 / IDENTITY PROVIDERS</span>
            <h3>Social login / OAuth</h3>
            <p>
              OAuth starts with browser navigation to the start endpoint.
              Central creates an OAuth transaction and a browser-binding cookie
              before redirecting the browser to the provider.
            </p>
            <div className="docs-provider-list">
              {oauthProviders.map((provider) => (
                <span className="docs-provider" key={provider}>{provider}</span>
              ))}
            </div>
            <div className="docs-oauth-flow">
              <div><span>01</span><strong>Start login</strong><code>GET /auth/oauth/:provider/start</code><p>Starts the login flow and redirects the browser to the provider's authorization URL (HTTP 302).</p></div>
              <div><span>02</span><strong>Provider callback</strong><code>GET /auth/oauth/:provider/callback</code><p>Receives the <code>code</code> and <code>state</code> query parameters, then validates the browser-binding cookie.</p></div>
              <div><span>03</span><strong>Central response</strong><code>HTTP 200 JSON</code><p>Successful login sets a session cookie. Successful account linking returns a linked status.</p></div>
            </div>
            <div className="docs-code-label">START LOGIN IN BROWSER</div>
            <pre className="docs-code"><code>{`const CENTRAL_API_URL = "https://your-central-public-origin";

window.location.assign(
  \`\${CENTRAL_API_URL}/auth/oauth/google/start\`
);`}</code></pre>
            <div className="docs-callout">
              <strong>Callback behavior</strong>
              <p>
                The callback currently returns JSON instead of redirecting to the
                dashboard. Successful login sets the
                <code> __Host-velzx_session</code> cookie; account linking returns
                the <code>linked</code> status. Do not assume the callback
                automatically navigates back to the portal.
              </p>
            </div>
            <h4>Account linking</h4>
            <p>
              <code>POST /auth/oauth/:provider/link/start</code> requires
              an active session and a matching <code>Origin</code> header. The endpoint
              starts the linking transaction and redirects the browser to the provider.
            </p>
            <p className="docs-muted">
              The OAuth callback and browser binding are managed as a browser-based flow.
              A standalone cURL request cannot replace the transaction cookie or
              state validation.
            </p>
          </section>

          <section className="docs-section content-card" id="docs-errors">
            <span className="docs-section-kicker">05 / TROUBLESHOOTING</span>
            <h3>Error responses</h3>
            <p>
              The Auth API returns JSON errors with the <code>status</code>,
              <code>code</code>, and <code>message</code> fields when the response
              includes a body.
            </p>
            <div className="docs-error-list">
              <div><code>401</code><strong>authentication_required</strong><span>The session is missing or inactive.</span></div>
              <div><code>403</code><strong>origin_rejected</strong><span>The request origin does not match the application configuration.</span></div>
              <div><code>404</code><strong>session_not_found</strong><span>The session was not found or does not belong to the current account.</span></div>
              <div><code>405</code><strong>method_not_allowed</strong><span>The HTTP method is not supported by this route.</span></div>
              <div><code>409</code><strong>ingress replay rejected</strong><span>The ingress request was detected as a replay.</span></div>
              <div><code>503</code><strong>ingress verification unavailable</strong><span>Ingress verification could not be completed.</span></div>
            </div>
            <p className="docs-muted">
              OAuth errors use codes specific to the transaction or provider.
              Public error messages are sanitized and do not expose internal details.
            </p>
          </section>

          <section className="docs-section content-card" id="docs-availability">
            <span className="docs-section-kicker">06 / IMPLEMENTATION STATUS</span>
            <h3>API availability</h3>
            <p>
              This portal documents the actual implementation status.
              The following endpoints are not yet available and must not be treated
              as callable APIs.
            </p>
            <div className="docs-unavailable-grid">
              {[
                'API key management',
                'Inference / chat completions',
                'Model registry',
                'Host registry',
                'Usage analytics',
                'Request logs',
              ].map((item) => (
                <div key={item}><span>—</span><strong>{item}</strong><small>NOT IMPLEMENTED</small></div>
              ))}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

function PlaygroundPage() {
  const [method, setMethod] = useState('POST');
  const [endpointPath, setEndpointPath] = useState('');
  const [headersText, setHeadersText] = useState(
    JSON.stringify({ 'Content-Type': 'application/json' }, null, 2)
  );
  const [bodyText, setBodyText] = useState('{}');
  const [copyState, setCopyState] = useState('');

  const headerResult = (() => {
    try {
      const value = JSON.parse(headersText);

      if (
        value === null ||
        typeof value !== 'object' ||
        Array.isArray(value)
      ) {
        return { error: 'Headers must be a JSON object.' };
      }

      return { value };
    } catch {
      return { error: 'Invalid JSON. Check your headers syntax.' };
    }
  })();

  function shellQuote(value) {
    return "'" + String(value).replace(/'/g, "'\\''") + "'";
  }

  const target = endpointPath
    ? `"$CENTRAL_API_URL"${shellQuote(endpointPath)}`
    : '"$CENTRAL_API_URL$ENDPOINT_PATH"';

  const curlLines = [
    `curl --request ${method} ${target}`,
  ];

  if (!headerResult.error) {
    Object.entries(headerResult.value).forEach(([key, value]) => {
      curlLines.push(
        `  --header ${shellQuote(`${key}: ${String(value)}`)}`
      );
    });
  }

  if (method !== 'GET' && method !== 'HEAD') {
    curlLines.push(`  --data-raw ${shellQuote(bodyText)}`);
  }

  const curlCommand = curlLines.join(
    ' ' + String.fromCharCode(92) + '\n'
  );

  async function copyCurl() {
    try {
      await navigator.clipboard.writeText(curlCommand);
      setCopyState('cURL copied to clipboard.');
    } catch {
      setCopyState(
        'Clipboard unavailable. Select and copy the command manually.'
      );
    }
  }

  return (
    <div className="playground-page">
      <section className="playground-notice">
        <span className="playground-notice-icon">◎</span>
        <div>
          <strong>Request execution is not available yet</strong>
          <p>
            Central inference endpoints are not implemented. You can
            prepare requests and copy the generated cURL command, but
            this Playground will not send network requests.
          </p>
        </div>
        <span className="playground-notice-status">NOT CONNECTED</span>
      </section>

      <div className="playground-workspace">
        <section className="playground-editor content-card">
          <div className="playground-panel-heading">
            <div>
              <h3>Request Builder</h3>
              <p>Configure an API request for your integration.</p>
            </div>
            <span className="playground-panel-icon">▷</span>
          </div>

          <div className="playground-field">
            <label htmlFor="playground-method">HTTP METHOD</label>
            <select
              id="playground-method"
              value={method}
              onChange={(event) => setMethod(event.target.value)}
            >
              <option value="POST">POST</option>
              <option value="GET">GET</option>
              <option value="PUT">PUT</option>
              <option value="PATCH">PATCH</option>
              <option value="DELETE">DELETE</option>
              <option value="HEAD">HEAD</option>
            </select>
          </div>

          <div className="playground-field">
            <label htmlFor="playground-path">ENDPOINT PATH</label>
            <input
              id="playground-path"
              type="text"
              value={endpointPath}
              onChange={(event) => setEndpointPath(event.target.value)}
              placeholder="Endpoint path not configured"
              spellCheck={false}
            />
            <small>
              Base URL is supplied through the CENTRAL_API_URL shell variable.
            </small>
          </div>

          <div className="playground-field">
            <label htmlFor="playground-headers">REQUEST HEADERS · JSON</label>
            <textarea
              id="playground-headers"
              value={headersText}
              onChange={(event) => {
                setHeadersText(event.target.value);
                setCopyState('');
              }}
              rows={5}
              spellCheck={false}
              className="playground-code-input"
            />
            {headerResult.error && (
              <small className="playground-field-error">
                {headerResult.error}
              </small>
            )}
          </div>

          <div className="playground-field">
            <label htmlFor="playground-body">REQUEST BODY · JSON</label>
            <textarea
              id="playground-body"
              value={bodyText}
              onChange={(event) => {
                setBodyText(event.target.value);
                setCopyState('');
              }}
              rows={9}
              spellCheck={false}
              className="playground-code-input playground-body-input"
              disabled={method === 'GET' || method === 'HEAD'}
            />
            <small>
              Request schema depends on the inference endpoint and model.
              No schema is currently registered.
            </small>
          </div>
        </section>

        <div className="playground-side">
          <section className="playground-preview content-card">
            <div className="playground-panel-heading">
              <div>
                <h3>Request Preview</h3>
                <p>Generated cURL command.</p>
              </div>
              <span className="playground-preview-label">PREVIEW</span>
            </div>

            <div className="playground-code-window">
              <div className="playground-code-topbar">
                <span>TERMINAL</span>
                <span>cURL</span>
              </div>
              <pre>{curlCommand}</pre>
            </div>

            <button
              type="button"
              className="playground-copy-button"
              onClick={copyCurl}
              disabled={Boolean(headerResult.error)}
            >
              <span>▣</span>
              Copy cURL
            </button>

            {copyState && (
              <p className="playground-copy-status" role="status">
                {copyState}
              </p>
            )}

            <div className="playground-env-note">
              <strong>Environment variables required</strong>
              <code>CENTRAL_API_URL</code>
              {!endpointPath && <code>ENDPOINT_PATH</code>}
              <small>
                Set these variables in your own terminal before running
                the generated command. No credentials are embedded.
              </small>
            </div>
          </section>

          <section className="playground-response content-card">
            <div className="playground-panel-heading">
              <div>
                <h3>Response Inspector</h3>
                <p>Execution results will appear here.</p>
              </div>
              <span className="playground-response-status">
                NOT EXECUTED
              </span>
            </div>

            <div className="playground-response-empty">
              <span>⌁</span>
              <h3>No response available</h3>
              <p>
                This Playground does not execute requests yet.
                Response body, HTTP status, and response timing will
                become available after inference integration.
              </p>
            </div>

            <div className="playground-response-meta">
              <div>
                <span>HTTP STATUS</span>
                <strong>—</strong>
              </div>
              <div>
                <span>RESPONSE TIME</span>
                <strong>—</strong>
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}


function AnalyticsPage() {
  const usageMetrics = [
    { label: 'TOTAL REQUESTS', value: '—', detail: 'Request metering unavailable', icon: '↗' },
    { label: 'INPUT TOKENS', value: '—', detail: 'Token metering unavailable', icon: '↓' },
    { label: 'OUTPUT TOKENS', value: '—', detail: 'Token metering unavailable', icon: '↑' },
    { label: 'SUCCESS RATE', value: '—', detail: 'Request metrics unavailable', icon: '✓' },
  ];

  const unavailableBreakdowns = [
    'Usage by model',
    'Usage by API key',
    'Token distribution',
    'Request distribution',
  ];

  return (
    <div className="analytics-page">
      <section className="analytics-status content-card">
        <div>
          <span className="analytics-eyebrow">ANALYTICS DATA SOURCE</span>
          <h3>Usage metering is not connected</h3>
          <p>
            Central usage metering and analytics endpoints are not yet
            implemented. Usage data will appear here when the backend is ready.
          </p>
        </div>
        <span className="analytics-status-label">
          <span className="analytics-status-dot" />
          DATA UNAVAILABLE
        </span>
      </section>

      <section className="analytics-metric-grid">
        {usageMetrics.map((metric) => (
          <article className="analytics-metric content-card" key={metric.label}>
            <div className="analytics-metric-top">
              <span>{metric.label}</span>
              <span className="analytics-metric-icon">{metric.icon}</span>
            </div>
            <strong>{metric.value}</strong>
            <p>{metric.detail}</p>
          </article>
        ))}
      </section>

      <section className="analytics-panel content-card">
        <div className="analytics-panel-heading">
          <div>
            <span className="analytics-eyebrow">REQUEST ACTIVITY</span>
            <h3>Request Volume</h3>
            <p>API request activity over time.</p>
          </div>
          <span className="analytics-unavailable-tag">NOT AVAILABLE</span>
        </div>
        <div className="analytics-empty">
          <div className="analytics-empty-icon">⌁</div>
          <strong>No request data available</strong>
          <p>
            The request metering service has not been connected.
            No sample or simulated activity is displayed.
          </p>
        </div>
      </section>

      <section className="analytics-panel content-card">
        <div className="analytics-panel-heading">
          <div>
            <span className="analytics-eyebrow">TOKEN CONSUMPTION</span>
            <h3>Token Usage</h3>
            <p>Input and output token consumption.</p>
          </div>
          <span className="analytics-unavailable-tag">NOT AVAILABLE</span>
        </div>
        <div className="analytics-empty">
          <div className="analytics-empty-icon">◇</div>
          <strong>Token metrics unavailable</strong>
          <p>
            Token usage cannot be calculated until inference and
            usage metering are implemented.
          </p>
        </div>
      </section>

      <section className="analytics-panel content-card">
        <div className="analytics-panel-heading">
          <div>
            <span className="analytics-eyebrow">USAGE DISTRIBUTION</span>
            <h3>Usage Breakdown</h3>
            <p>Detailed consumption across Central resources.</p>
          </div>
          <span className="analytics-unavailable-tag">PENDING</span>
        </div>
        <div className="analytics-breakdown-grid">
          {unavailableBreakdowns.map((item) => (
            <div className="analytics-breakdown-item" key={item}>
              <span>—</span>
              <strong>{item}</strong>
              <small>DATA UNAVAILABLE</small>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}


function RequestLogsPage() {
  const metrics = [
    {
      label: 'TOTAL REQUESTS',
      value: '—',
      detail: 'Request data unavailable',
      icon: '↗',
    },
    {
      label: 'SUCCESSFUL REQUESTS',
      value: '—',
      detail: 'Response status unavailable',
      icon: '✓',
    },
    {
      label: 'FAILED REQUESTS',
      value: '—',
      detail: 'Error metrics unavailable',
      icon: '!',
    },
    {
      label: 'AVERAGE LATENCY',
      value: '—',
      detail: 'Latency metrics unavailable',
      icon: '◷',
    },
  ];

  const columns = [
    'REQUEST ID',
    'TIMESTAMP',
    'METHOD',
    'ENDPOINT',
    'HTTP STATUS',
    'LATENCY',
  ];

  return (
    <div className="request-logs-page">
      <section className="logs-source-status content-card">
        <div>
          <span className="logs-eyebrow">LOGGING DATA SOURCE</span>
          <h3>Request logging is not connected</h3>
          <p>
            Central request logging and log retrieval endpoints are not yet
            implemented. Request history will appear here when the backend
            integration becomes available.
          </p>
        </div>
        <span className="logs-status-label">
          <span className="logs-status-dot" />
          DATA UNAVAILABLE
        </span>
      </section>

      <section className="logs-metric-grid">
        {metrics.map((metric) => (
          <article className="logs-metric content-card" key={metric.label}>
            <div className="logs-metric-top">
              <span>{metric.label}</span>
              <span className="logs-metric-icon">{metric.icon}</span>
            </div>
            <strong>{metric.value}</strong>
            <p>{metric.detail}</p>
          </article>
        ))}
      </section>

      <section className="logs-history content-card">
        <div className="logs-history-heading">
          <div>
            <span className="logs-eyebrow">REQUEST INSPECTION</span>
            <h3>Request History</h3>
            <p>
              Inspect API request metadata, response status, and latency.
            </p>
          </div>
          <span className="logs-unavailable-tag">NOT AVAILABLE</span>
        </div>

        <div className="logs-table-wrapper">
          <table className="logs-table">
            <thead>
              <tr>
                {columns.map((column) => (
                  <th key={column}>{column}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              <tr>
                <td colSpan={columns.length}>
                  <div className="logs-empty">
                    <div className="logs-empty-icon">≡</div>
                    <strong>No request logs available</strong>
                    <p>
                      The request logging service has not been implemented
                      or connected. No sample records are displayed.
                    </p>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="logs-information content-card">
        <span className="logs-eyebrow">LOG DATA REFERENCE</span>
        <h3>Request metadata</h3>
        <p>
          The table structure is prepared for actual request log records.
          These fields will be populated only when a supported logging
          service is connected.
        </p>
        <div className="logs-field-grid">
          {columns.map((column) => (
            <div className="logs-field-item" key={column}>
              <span>—</span>
              <strong>{column}</strong>
              <small>AWAITING DATA</small>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}


function AccountSettingsPage() {
  return (
    <div className="account-settings-page">
      <section className="account-settings-overview">
        <div className="account-settings-overview-copy">
          <span className="account-settings-kicker">ACCOUNT OVERVIEW</span>
          <h3>Developer Account</h3>
          <p>
            Review your account identity and current account status.
            Account information will appear after the Central API integration
            is available.
          </p>
        </div>
        <div className="account-settings-status">
          <span className="account-settings-status-dot" />
          API NOT CONNECTED
        </div>
      </section>

      <section className="account-settings-grid">
        <article className="account-settings-card">
          <span className="account-settings-card-icon">◇</span>
          <span className="account-settings-label">ACCOUNT ID</span>
          <strong>—</strong>
          <p>Account identifier unavailable</p>
        </article>
        <article className="account-settings-card">
          <span className="account-settings-card-icon">✉</span>
          <span className="account-settings-label">EMAIL ADDRESS</span>
          <strong>—</strong>
          <p>Account email unavailable</p>
        </article>
        <article className="account-settings-card">
          <span className="account-settings-card-icon">◈</span>
          <span className="account-settings-label">ACCOUNT STATUS</span>
          <strong>—</strong>
          <p>Account status unavailable</p>
        </article>
        <article className="account-settings-card">
          <span className="account-settings-card-icon">✓</span>
          <span className="account-settings-label">EMAIL VERIFICATION</span>
          <strong>—</strong>
          <p>Verification status unavailable</p>
        </article>
      </section>

      <section className="account-settings-panel">
        <div className="account-settings-panel-heading">
          <div>
            <span className="account-settings-kicker">ACCOUNT DETAILS</span>
            <h3>Account Information</h3>
            <p>Information associated with your authenticated Central account.</p>
          </div>
          <span className="account-settings-tag">AWAITING API</span>
        </div>
        <div className="account-settings-details">
          <div className="account-settings-detail">
            <span>Account ID</span><strong>—</strong>
          </div>
          <div className="account-settings-detail">
            <span>Email Address</span><strong>—</strong>
          </div>
          <div className="account-settings-detail">
            <span>Account Status</span><strong>—</strong>
          </div>
          <div className="account-settings-detail">
            <span>Email Verified</span><strong>—</strong>
          </div>
        </div>
      </section>

      <section className="account-settings-panel">
        <div className="account-settings-panel-heading">
          <div>
            <span className="account-settings-kicker">PREFERENCES</span>
            <h3>Account Preferences</h3>
            <p>Account preference controls are not available yet.</p>
          </div>
          <span className="account-settings-tag">NOT AVAILABLE</span>
        </div>
        <div className="account-settings-notice">
          <span className="account-settings-notice-icon">⚙</span>
          <div>
            <strong>Preference management is not implemented</strong>
            <p>
              No editable settings are displayed until supported backend
              capabilities are implemented.
            </p>
          </div>
        </div>
      </section>

      <section className="account-settings-integration">
        <div className="account-settings-integration-icon">⇄</div>
        <div>
          <span className="account-settings-kicker">INTEGRATION STATUS</span>
          <h3>Account API is not connected</h3>
          <p>
            Central provides an authenticated account endpoint, but the
            Developer Portal does not yet have a verified public API
            integration. Account information remains unavailable until that
            connection is implemented.
          </p>
        </div>
        <span className="account-settings-tag">PENDING</span>
      </section>
    </div>
  );
}

function UnavailablePage({ pageId }) {
  const info = pageInfo[pageId];

  return (
    <section className="page-placeholder">
      <div className="placeholder-icon">◇</div>
      <span className="placeholder-label">WORKSPACE MODULE</span>
      <h3>{info.title}</h3>
      <p>{info.description}</p>
      <div className="availability-state">
        <span className="availability-dot" />
        UI ready · Backend integration pending
      </div>
      <p className="placeholder-note">
        This section will become functional when its corresponding Central
        API capability is implemented and connected. No sample records or
        simulated results are displayed.
      </p>
    </section>
  );
}


function AuthPage({ mode }) {
  const isRegister = mode === 'register';

  const providers = [
    { id: 'google', name: 'Google', mark: 'G' },
    { id: 'github', name: 'GitHub', mark: '⌘' },
    { id: 'microsoft', name: 'Microsoft', mark: '▦' },
  ];

  return (
    <main className="auth-page">
      <div className="auth-background-glow" aria-hidden="true" />

      <section className="auth-shell">
        <a className="auth-brand" href="/login" aria-label="VELZX AI Central">
          <span className="auth-brand-symbol">V</span>
          <span className="auth-brand-copy">
            <strong>VELZX</strong>
            <small>AI CENTRAL</small>
          </span>
        </a>

        <div className="auth-card">
          <div className="auth-card-heading">
            <span className="auth-eyebrow">DEVELOPER IDENTITY</span>
            <h1>{isRegister ? 'Create your account' : 'Welcome back'}</h1>
            <p>
              {isRegister
                ? 'Create your VELZX AI Central developer identity.'
                : 'Sign in to access your VELZX AI Central workspace.'}
            </p>
          </div>

          <div className="auth-provider-heading">
            <span>CONTINUE WITH</span>
            <span className="auth-provider-status">NOT CONNECTED</span>
          </div>

          <div className="auth-provider-list">
            {providers.map((provider) => (
              <button
                className="auth-provider-button"
                type="button"
                disabled
                aria-disabled="true"
                key={provider.id}
                title={`${provider.name} sign-in is not connected yet`}
              >
                <span className={`auth-provider-mark auth-mark-${provider.id}`}>
                  {provider.mark}
                </span>
                <span>{provider.name}</span>
                <span className="auth-provider-unavailable">Unavailable</span>
              </button>
            ))}
          </div>

          <div className="auth-integration-notice" role="status">
            <span className="auth-notice-icon">i</span>
            <p>
              Social authentication is not connected to this frontend yet.
              No sign-in request has been sent.
            </p>
          </div>

          <div className="auth-switch">
            <span>
              {isRegister
                ? 'Already have an account?'
                : "Don't have an account?"}
            </span>
            <a href={isRegister ? '/login' : '/register'}>
              {isRegister ? 'Sign in' : 'Create account'}
            </a>
          </div>
        </div>

        <footer className="auth-footer">
          <span>© 2026 VELZX AI Central</span>
          <span>Developer Portal</span>
        </footer>
      </section>
    </main>
  );
}

function App() {
  const pathname = window.location.pathname.replace(/\/+$/, '') || '/';

  if (pathname === '/login') {
    return <AuthPage mode="login" />;
  }

  if (pathname === '/register') {
    return <AuthPage mode="register" />;
  }

  return <DashboardApp />;
}

function DashboardApp() {
  const [activePage, setActivePage] = useState('overview');
  const [mobileOpen, setMobileOpen] = useState(false);
  const currentPage = pageInfo[activePage];

  function navigate(pageId) {
    setActivePage(pageId);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  return (
    <div className="portal">
      <Sidebar
        activePage={activePage}
        onNavigate={navigate}
        mobileOpen={mobileOpen}
        onClose={() => setMobileOpen(false)}
      />

      <div className="main-shell">
        <Header
          title={currentPage.title}
          onMenuClick={() => setMobileOpen(true)}
        />

        <main className="page-content">
          {activePage === 'overview' ? (
            <Overview onNavigate={navigate} />
          ) : (
            <>
              <SectionHeading
                eyebrow="DEVELOPER PORTAL"
                title={currentPage.title}
                description={currentPage.description}
              />
              {activePage === 'api-keys' ? (
                <ApiKeysPage />
              ) : activePage === 'models' ? (
                <ModelsPage />
              ) : activePage === 'documentation' ? (
                <DocumentationPage />
              ) : activePage === 'analytics' ? (
                <AnalyticsPage />
              ) : activePage === 'logs' ? (
                <RequestLogsPage />
              ) : activePage === 'settings' ? (
                <AccountSettingsPage />
              ) : activePage === 'playground' ? (
                <PlaygroundPage />
              ) : (
                <UnavailablePage pageId={activePage} />
              )}
            </>
          )}

          <footer className="page-footer">
            <span>© 2026 VELZX AI Central</span>
            <span>Developer Portal</span>
          </footer>
        </main>
      </div>
    </div>
  );
}

export default App;
