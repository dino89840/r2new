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

    // Heartbeat — connection timeout မဖြစ်အောင် 5 စက္ကန့်တိုင်း SSE comment ပို့ပေးတယ်
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

    // Upload logic ကို stream အတွင်းမှာပဲ run တယ်
    // waitUntil ထဲထည့်တာက stream ကို alive ဖြစ်စေတာ မဟုတ်ဘူး
    // ဒါကြောင့် upload ပြီးမှ stream ပိတ်အောင် ဒီ async block ကိုပဲ waitUntil ထဲထည့်ပြီး
    // readable stream ကို return လုပ်တယ်
    const uploadAndStream = async () => {
      try {
        // Upload မစခင် initial event ပို့ပေးတယ်
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

    // waitUntil က worker ကို upload မပြီးခင် kill မလုပ်အောင် ကာကွယ်ပေးတယ်
    context.waitUntil(uploadAndStream());

    return new Response(readable, {
      status: 200,
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no", // Nginx/proxy buffering ပိတ်
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
