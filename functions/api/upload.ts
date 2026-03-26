import { handleUpload, type Env } from "../../src/r2-uploader";

export const onRequestPost: PagesFunction<Env> = async (context) => {
  try {
    const result = await handleUpload(context.request, context.env);

    return new Response(JSON.stringify(result), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (err) {
    const message = (err as Error).message || "Upload failed";
    console.error("Upload error:", message);

    return new Response(JSON.stringify({ error: message }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
};
