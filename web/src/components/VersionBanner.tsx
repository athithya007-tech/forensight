import { useHealth } from "../api/client";
import { APP_VERSION } from "../version";

/** The most common "it still fails after I updated" cause: an old `forensight serve` is still running the old code.
 *  The dashboard knows its own version; if the server reports a different one, say exactly what to do. */
export function VersionBanner() {
  const h = useHealth();
  if (!h.data || h.data.version === APP_VERSION) return null;
  return (
    <div role="alert" className="border-b border-tape/40 bg-tape/10 px-4 py-2.5 text-sm text-ink lg:px-8">
      <b>The server is running an older version{h.data.version ? ` (${h.data.version})` : ""} than this dashboard ({APP_VERSION}).</b>{" "}
      Reports and new features may fail. In the terminal running <code className="font-mono text-xs">forensight serve</code>, press
      <kbd className="mx-1 rounded border border-rule px-1 font-mono text-xs">Ctrl+C</kbd>, run
      <code className="mx-1 font-mono text-xs">pip install -e .</code> and start <code className="font-mono text-xs">forensight serve</code> again.
      <code className="ml-1 font-mono text-xs">forensight doctor</code> checks everything.
    </div>
  );
}
