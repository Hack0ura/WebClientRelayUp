
namespace HttpLdapRelay
{
    /// <summary>
    /// Manages an NTLM relay session between HTTP client and LDAP server
    /// </summary>
    public class NtlmRelaySession
    {
        public string SessionId { get; private set; }
        public LdapRelayClient LdapClient { get; set; }
        public string TargetServer { get; set; }
        public int TargetPort { get; set; }
        public bool UseLdaps { get; set; }
        public SessionState State { get; set; }
        public DateTime CreatedAt { get; set; }
        public string ClientIdentity { get; set; }

        public NtlmRelaySession(string sessionId)
        {
            SessionId = sessionId;
            State = SessionState.Initial;
            CreatedAt = DateTime.Now;
        }
    }

    public enum SessionState
    {
        Initial,
        Type1Sent,
        Type2Received,
        Type3Sent,
        Authenticated,
        Failed
    }

    /// <summary>
    /// Manages multiple NTLM relay sessions
    /// </summary>
    public class SessionManager
    {
        private readonly Dictionary<string, NtlmRelaySession> _sessions;
        private readonly object _lock = new object();

        public SessionManager()
        {
            _sessions = new Dictionary<string, NtlmRelaySession>();
        }

        public NtlmRelaySession CreateSession()
        {
            lock (_lock)
            {
                string sessionId = Guid.NewGuid().ToString("N");
                var session = new NtlmRelaySession(sessionId);
                _sessions[sessionId] = session;

                // Cleanup old sessions (> 5 minutes)
                CleanupOldSessions();

                return session;
            }
        }

        public NtlmRelaySession GetSession(string sessionId)
        {
            lock (_lock)
            {
                if (_sessions.TryGetValue(sessionId, out var session))
                {
                    return session;
                }
                return null;
            }
        }

        public void RemoveSession(string sessionId)
        {
            lock (_lock)
            {
                if (_sessions.TryGetValue(sessionId, out var session))
                {
                    // Cleanup LDAP connection
                    session.LdapClient?.Dispose();
                    _sessions.Remove(sessionId);
                }
            }
        }

        private void CleanupOldSessions()
        {
            var toRemove = new List<string>();
            var threshold = DateTime.Now.AddMinutes(-5);

            foreach (var kvp in _sessions)
            {
                if (kvp.Value.CreatedAt < threshold)
                {
                    toRemove.Add(kvp.Key);
                }
            }

            foreach (var sessionId in toRemove)
            {
                RemoveSession(sessionId);
            }
        }
    }
}