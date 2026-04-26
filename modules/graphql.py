"""
VULNIX - GraphQL Security Scanner
Detects GraphQL endpoints and tests for common vulnerabilities
"""

import re
import json
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

from core.request_engine import RequestEngine
from core.error_collector import ModuleErrorCollector


GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/api/v1/graphql",
    "/graph",
    "/api/graph",
    "/gql",
    "/query",
    "/v1/query",
]

GRAPHQL_INTROSPECTION = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      enumValues(includeDeprecated: true) {
        name
        isDeprecated
        deprecationReason
      }
      inputFields {
        name
        type {
          kind
          name
          ofType { kind name }
        }
      }
      fields(includeDeprecated: true) {
        name
        args {
          name
          description
          type { kind name }
          defaultValue
        }
        type { kind name }
        isDeprecated
        deprecationReason
      }
    }
    directives {
      name
      description
      locations
      args {
        name
        type { kind name }
        defaultValue
      }
    }
  }
}
"""

COMMON_MUTATION_KEYWORDS = [
    "delete", "remove", "destroy", "update", "create", "insert",
    "add", "edit", "modify", "change", "reset", "upload",
]

BATCHING_PAYLOAD = [
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
]

ALIAS_OVERLOAD = """
query {
  a1: login { token }
  a2: login { token }
  a3: login { token }
  a4: login { token }
  a5: login { token }
  a6: login { token }
  a7: login { token }
  a8: login { token }
  a9: login { token }
  a10: login { token }
  a11: login { token }
  a12: login { token }
  a13: login { token }
  a14: login { token }
  a15: login { token }
  a16: login { token }
  a17: login { token }
  a18: login { token }
  a19: login { token }
  a20: login { token }
}
"""

DEEP_NESTING = """
query q1 {
  q2: root {
    q3: child {
      q4: child {
        q5: child {
          q6: child {
            q7: child {
              q8: child {
                q9: child {
                  q10: child {
                    field
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
"""


class GraphQLScanner:
    """Scan GraphQL endpoints for security vulnerabilities."""

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine
        self.error_collector = ModuleErrorCollector("graphql")
        self.found_schema = False
        self.schema: Dict[str, Any] = {}
        self.mutations: List[str] = []
        self.queries: List[str] = []

    def _normalize_url(self, target: str) -> str:
        """Normalize target to URL with scheme."""
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        return target.rstrip("/")

    def _extract_graphql_paths(self, target: str) -> List[str]:
        """Generate potential GraphQL endpoint paths."""
        base = self._normalize_url(target)
        parsed = urlparse(base)
        paths = [f"{parsed.path}/{p.lstrip('/')}" for p in GRAPHQL_PATHS]
        return list(set(paths))

    async def find_endpoint(self, target: str) -> Optional[str]:
        """Find GraphQL endpoint by probing common paths."""
        base = self._normalize_url(target)

        for path in GRAPHQL_PATHS:
            url = f"{base.rstrip('/')}/{path.lstrip('/')}"

            try:
                response = await self.request_engine.post(
                    url,
                    json={"query": "{ __typename }"},
                    headers={"Content-Type": "application/json"},
                )

                if response and response.status_code == 200:
                    try:
                        data = response.json()
                        if "data" in data or "errors" in data:
                            return url
                    except Exception:
                        pass

            except Exception as e:
                self.error_collector.add(url, e, "probe_endpoint")

        return None

    async def introspect(self, endpoint: str) -> Optional[Dict[str, Any]]:
        """Perform GraphQL introspection query."""
        try:
            response = await self.request_engine.post(
                endpoint,
                json={"query": GRAPHQL_INTROSPECTION},
                headers={"Content-Type": "application/json"},
            )

            if response and response.status_code == 200:
                try:
                    data = response.json()
                    if "data" in data and data["data"]:
                        self.schema = data["data"].get("__schema", {})
                        self._extract_operations()
                        return self.schema
                except Exception as e:
                    self.error_collector.add(endpoint, e, "introspection")

        except Exception as e:
            self.error_collector.add(endpoint, e, "introspect_request")

        return None

    def _extract_operations(self) -> None:
        """Extract queries and mutations from schema."""
        if not self.schema:
            return

        for t in self.schema.get("types", []):
            if t.get("kind") == "OBJECT":
                name = t.get("name", "")
                if name.startswith("Query"):
                    for f in t.get("fields", []):
                        self.queries.append(f.get("name", ""))
                elif name.startswith("Mutation"):
                    for f in t.get("fields", []):
                        name = f.get("name", "")
                        self.mutations.append(name)
                        for kw in COMMON_MUTATION_KEYWORDS:
                            if kw.lower() in name.lower():
                                self.mutations.append(f"SENSITIVE:{name}")

    async def test_introspection(self, endpoint: str) -> List[Dict[str, Any]]:
        """Test if introspection is enabled."""
        findings = []

        try:
            result = await self.introspect(endpoint)

            if result:
                findings.append({
                    "type": "graphql_introspection",
                    "severity": "info",
                    "description": "GraphQL introspection enabled - schema publicly accessible",
                    "endpoint": endpoint,
                })
            else:
                findings.append({
                    "type": "graphql_introspection_blocked",
                    "severity": "low",
                    "description": "GraphQL introspection appears disabled or blocked",
                    "endpoint": endpoint,
                })

        except Exception as e:
            self.error_collector.add(endpoint, e, "test_introspection")

        return findings

    async def test_batching(self, endpoint: str) -> List[Dict[str, Any]]:
        """Test for GraphQL batching vulnerability."""
        findings = []

        try:
            response = await self.request_engine.post(
                endpoint,
                json=BATCHING_PAYLOAD,
                headers={"Content-Type": "application/json"},
            )

            if response and response.status_code == 200:
                try:
                    data = response.json()
                    if isinstance(data, list) and len(data) == 10:
                        findings.append({
                            "type": "graphql_batching",
                            "severity": "medium",
                            "description": "GraphQL batching enabled - allows multiple operations in single request",
                            "endpoint": endpoint,
                        })
                except Exception:
                    pass

        except Exception as e:
            self.error_collector.add(endpoint, e, "test_batching")

        return findings

    async def test_alias_overload(self, endpoint: str) -> List[Dict[str, Any]]:
        """Test for alias overloading DoS."""
        findings = []

        try:
            response = await self.request_engine.post(
                endpoint,
                json={"query": ALIAS_OVERLOAD},
                headers={"Content-Type": "application/json"},
            )

            if response and response.status_code == 200:
                findings.append({
                    "type": "graphql_alias_overload",
                    "severity": "medium",
                    "description": "GraphQL accepts aliased queries - potential DoS vector",
                    "endpoint": endpoint,
                })

        except Exception as e:
            self.error_collector.add(endpoint, e, "test_alias")

        return findings

    async def test_deep_nesting(self, endpoint: str) -> List[Dict[str, Any]]:
        """Test for deeply nested query DoS."""
        findings = []

        try:
            response = await self.request_engine.post(
                endpoint,
                json={"query": DEEP_NESTING},
                headers={"Content-Type": "application/json"},
            )

            if response:
                findings.append({
                    "type": "graphql_deep_nesting",
                    "severity": "medium",
                    "description": "GraphQL accepts deeply nested queries",
                    "endpoint": endpoint,
                })

        except Exception as e:
            self.error_collector.add(endpoint, e, "test_nesting")

        return findings

    async def test_dangerous_mutations(self, endpoint: str) -> List[Dict[str, Any]]:
        """Test for dangerous mutations."""
        findings = []

        sensitive = [m for m in self.mutations if m.startswith("SENSITIVE:")]

        if sensitive:
            findings.append({
                "type": "graphql_sensitive_mutations",
                "severity": "info",
                "description": f"Found {len(sensitive)} sensitive mutations (may require auth)",
                "endpoint": endpoint,
                "details": {"mutations": sensitive},
            })

        return findings

    async def scan(self, target: str) -> List[Dict[str, Any]]:
        """Perform complete GraphQL security scan."""
        findings = []

        endpoint = await self.find_endpoint(target)

        if not endpoint:
            return findings

        findings.append({
            "type": "graphql_endpoint",
            "severity": "info",
            "description": f"GraphQL endpoint found: {endpoint}",
            "endpoint": endpoint,
        })

        findings.extend(await self.test_introspection(endpoint))
        findings.extend(await self.test_batching(endpoint))
        findings.extend(await self.test_alias_overload(endpoint))
        findings.extend(await self.test_deep_nesting(endpoint))
        findings.extend(await self.test_dangerous_mutations(endpoint))

        return findings

    def get_errors(self) -> List[Dict[str, Any]]:
        """Get collected errors."""
        return self.error_collector.all()