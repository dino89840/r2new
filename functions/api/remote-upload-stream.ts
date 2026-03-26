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

    // SSE streaming response using TransformStream
    const { readable, writable } = new TransformStream();
    const writer = writable.getWriter();
    const encoder = new TextEncoder();

    const sendSSE = async (data: Record<string, unknown>) => {
      try {
        await writer.write(encoder.encode(`data: ${JSON.stringify(data)}\n\n`));
      } catch {
        // Stream might be closed
      }
    };

    // Run the upload in the background
    // Use context.waitUntil to keep the worker alive
    const uploadPromise = (async () => {
      try {
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
        try {
          await writer.close();
        } catch {
          // Already closed
        }
      }
    })();

    // Keep the worker alive for the upload
    context.waitUntil(uploadPromise);

    return new Response(readable, {
      status: 200,
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
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
