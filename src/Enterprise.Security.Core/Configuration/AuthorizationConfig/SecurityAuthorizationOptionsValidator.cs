
using Enterprise.Security.Core.Configuration.AuthorizationConfig;

namespace Enterprise.Security.Core.Configuration;

public static class SecurityAuthorizationOptionsValidator
{
    public static void Validate(SecurityAuthorizationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        // Disabled features do not require configuration.
        if (!options.Enabled)
            return;

        if (options.Policies is null)
        {
            throw new InvalidOperationException("Authorization policies configuration cannot be null.");
        }

        foreach (var (policyName, policy) in options.Policies)
        {
            // Validate policy name.
            if (string.IsNullOrWhiteSpace(policyName))
            {
                throw new InvalidOperationException(
                    "Authorization policy names cannot be empty.");
            }

            // Validate policy configuration.
            if (policy is null)
            {
                throw new InvalidOperationException($"Authorization policy '{policyName}' cannot be null.");
            }

            // Validate permissions.
            ValidateEntries(policyName, "permission", policy.RequiredPermissions);

            // Validate referenced policies.
            ValidateEntries(policyName, "referenced policy", policy.RequiredPolicies);

            // Validate role groups.
            if (policy.RoleGroups is null)
            {
                throw new InvalidOperationException($"Authorization policy '{policyName}' has null role groups.");
            }

            foreach (var group in policy.RoleGroups)
            {
                if (group is null || group.Count == 0 || group.Any(string.IsNullOrWhiteSpace))
                {
                    throw new InvalidOperationException($"Authorization policy '{policyName}' contains an invalid role group.");
                }
            }

            if (policy.RequiredPermissions.Count == 0 && policy.RoleGroups.Count == 0 && policy.RequiredPolicies.Count == 0)
            {
                throw new InvalidOperationException($"Authorization policy '{policyName}' must define at least one permission, role group, or referenced policy.");
            }

            // Validate referenced policies exist.
            foreach (var referencedPolicy in policy.RequiredPolicies)
            {
                if (!options.Policies.ContainsKey(referencedPolicy))
                {
                    throw new InvalidOperationException($"Authorization policy '{policyName}' references unknown policy '{referencedPolicy}'.");
                }
            }
        }

        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var visiting = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var policyName in options.Policies.Keys)
        {
            Visit(policyName);
        }

        void Visit(string name)
        {
            if (visiting.Contains(name))
            {
                throw new InvalidOperationException($"Circular authorization policy reference detected at '{name}'.");
            }

            if (visited.Contains(name))
                return;

            visiting.Add(name);

            foreach (var dependency in options.Policies[name].RequiredPolicies)
            {
                Visit(dependency);
            }

            visiting.Remove(name);
            visited.Add(name);
        }
    }

    private static void ValidateEntries(string policyName, string entryType, List<string>? entries)
    {
        if (entries is null || entries.Any(string.IsNullOrWhiteSpace))
        {
            throw new InvalidOperationException($"Authorization policy '{policyName}' contains invalid {entryType} entries.");
        }
    }
}
