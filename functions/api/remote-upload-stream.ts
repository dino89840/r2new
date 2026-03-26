import { handleRemoteUpload, type Env } from "../../src/r2-uploader";

export const onRequestPost: PagesFunction<Env> = async (context) => {
  try {
    const body = await context.request.json<{ url: string }>();
    const remoteUrl = body.url;

    if (!remoteUrl) {
      return new Response(JSON.stringify({ error: "No URL provided" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    const { readable, writable } = new TransformStream();
    const writer = writable.getWriter();
    const encoder = new TextEncoder();

    let streamClosed = false;

    const sendSSE = async (data: Record<string, unknown>) => {
      if (streamClosed) return;
      try {
        await writer.write(encoder.encode(`data: ${JSON.stringify(data)}\n\n`));
      } catch {
        streamClosed = true;
      }
    };

    // Heartbeat every 5s to keep connection alive
    const heartbeatInterval = setInterval(async () => {
      if (streamClosed) {
        clearInterval(heartbeatInterval);
        return;
      }
      try {
        await writer.write(encoder.encode(`: heartbeat\n\n`));
      } catch {
        streamClosed = true;
        clearInterval(heartbeatInterval);
      }
    }, 5000);

    const uploadAndStream = async () => {
      try {
        await sendSSE({ type: "start", message: "Upload starting..." });

        const result = await handleRemoteUpload(
          remoteUrl,
          context.env,
          async (progress) => {
            await sendSSE({
              type: "progress",
              ...progress,
            });
          }
        );

        await sendSSE({
          type: "done",
          filename: result.filename,
          size: result.size,
          links: result.links,
          uploadedTo: result.uploadedTo,
        });
      } catch (err) {
        const message = (err as Error).message || "Remote upload failed";
        console.error("Remote upload error:", message);
        await sendSSE({ type: "error", error: message });
      } finally {
        clearInterval(heartbeatInterval);
        streamClosed = true;
        try {
          await writer.close();
        } catch {
          // Already closed
        }
      }
    };

    context.waitUntil(uploadAndStream());

    return new Response(readable, {
      status: 200,
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
      },
    });
  } catch (err) {
    const message = (err as Error).message || "Request failed";
    return new Response(JSON.stringify({ error: message }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
};
