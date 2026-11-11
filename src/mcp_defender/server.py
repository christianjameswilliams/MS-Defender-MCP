"""MCP server for Microsoft Defender Advanced Hunting.

Uses the unified Microsoft 365 Defender API for Advanced Hunting queries
across Device, Identity, Email, Cloud App, and AI workloads.
"""

import os
from typing import Any, cast

import httpx
from azure.identity import CertificateCredential, ClientSecretCredential
from dotenv import load_dotenv
from mcp.server import MCPServer

load_dotenv()

server = MCPServer("mcp-defender")

DEFENDER_API_BASE = "https://api.security.microsoft.com"
DEFENDER_SCOPE = "https://api.security.microsoft.com/.default"

_credential: CertificateCredential | ClientSecretCredential | None = None


def get_credential() -> CertificateCredential | ClientSecretCredential:
    """Get or create the Azure credential."""

    global _credential

    if _credential is None:
        tenant_id = os.environ.get("AZURE_TENANT_ID")
        client_id = os.environ.get("AZURE_CLIENT_ID")
        client_secret = os.environ.get("AZURE_CLIENT_SECRET")
        certificate_path = os.environ.get(
            "AZURE_CLIENT_CERTIFICATE_PATH"
        )
        certificate_password = os.environ.get(
            "AZURE_CLIENT_CERTIFICATE_PASSWORD"
        )

        if not tenant_id or not client_id:
            raise ValueError(
                "Missing Azure credentials. Set AZURE_TENANT_ID and "
                "AZURE_CLIENT_ID."
            )

        if certificate_path:
            _credential = CertificateCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                certificate_path=certificate_path,
                password=certificate_password,
            )
        elif client_secret:
            _credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )
        else:
            raise ValueError(
                "Missing authentication method. Set "
                "AZURE_CLIENT_CERTIFICATE_PATH or AZURE_CLIENT_SECRET."
            )

    return _credential


def get_access_token() -> str:
    """Get an access token for the Defender API."""

    credential = get_credential()
    token = credential.get_token(DEFENDER_SCOPE)
    return token.token


async def run_defender_query(query: str) -> dict[str, Any]:
    """Execute a query against the Defender Advanced Hunting API."""

    token = get_access_token()

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{DEFENDER_API_BASE}/api/advancedhunting/run",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json={"Query": query},
            timeout=120.0,
        )

        response.raise_for_status()
        return cast(dict[str, Any], response.json())


@server.tool()
async def run_hunting_query(query: str) -> str:
    """Execute a KQL query against Microsoft Defender Advanced Hunting.

    Use this tool to investigate security events across endpoints, email,
    identity, cloud applications, and other Defender workloads. Retrieve
    the hunting schema before constructing queries against unfamiliar
    tables.
    """

    try:
        result = await run_defender_query(query)

        output_lines: list[str] = []

        schema = result.get("Schema", [])
        results = result.get("Results", [])

        if schema:
            headers = [column.get("Name", "") for column in schema]
            output_lines.append(" | ".join(headers))
            output_lines.append("-" * 80)

            for row in results:
                values = [
                    str(row.get(column.get("Name", ""), ""))
                    for column in schema
                ]
                output_lines.append(" | ".join(values))
        else:
            for row in results:
                output_lines.append(str(row))

        if not output_lines:
            return "Query returned no results."

        stats = result.get("Stats", {})

        if stats:
            output_lines.append("")
            output_lines.append("--- Query Stats ---")
            output_lines.append(
                f"Execution time: {stats.get('ExecutionTime', 'N/A')}"
            )
            output_lines.append(f"Rows returned: {len(results)}")

        return "\n".join(output_lines)

    except httpx.HTTPStatusError as error:
        error_detail = (
            error.response.text if error.response else str(error)
        )
        return f"Query error: {error_detail}"

    except Exception as error:
        return f"Query error: {error}"


@server.tool()
async def get_hunting_schema(table_name: str | None = None) -> str:
    """Retrieve Microsoft Defender Advanced Huntingschema information.

    When table_name is provided, return the columns for that table.
    When table_name is omitted, return the available hunting tables.
    """

    try:
        if table_name:
            result = await run_defender_query(
                f"{table_name} | getschema"
            )

            schema_results = result.get("Results", [])

            if not schema_results:
                return f"Table '{table_name}' was not found."

            output = [f"Schema for {table_name}:", ""]

            for row in schema_results:
                column_name = row.get("ColumnName", "")
                column_type = row.get("ColumnType", "")
                output.append(f"  {column_name}: {column_type}")

            return "\n".join(output)

        result = await run_defender_query(
            "search * | distinct $table | sort by $table asc"
        )

        tables = result.get("Results", [])

        if not tables:
            return "Could not retrieve the Advanced Hunting schema."

        output = ["Available Advanced Hunting Tables:", ""]

        for row in tables:
            table = row.get("$table", "")

            if table:
                output.append(f"  {table}")

        output.append("")
        output.append(
            "Call get_hunting_schema with table_name to see its columns."
        )

        return "\n".join(output)

    except httpx.HTTPStatusError as error:
        error_detail = (
            error.response.text if error.response else str(error)
        )
        return f"Schema error: {error_detail}"

    except Exception as error:
        return f"Schema error: {error}"


def main() -> None:
    """Run the MCP server using Streamable HTTP."""

    port = int(os.environ.get("PORT", "8000"))

    server.run(
        transport="streamable-http",
	host="0.0.0.0",
        port=port,
    )


if __name__ == "__main__":
    main()
