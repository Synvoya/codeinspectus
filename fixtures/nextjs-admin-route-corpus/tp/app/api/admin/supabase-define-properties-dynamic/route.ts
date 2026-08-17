import { createClient } from "@supabase/supabase-js";

export async function DELETE(descriptors: PropertyDescriptorMap) {
  const supabase = createClient("https://example.supabase.co", "publishable-key");
  Object.defineProperties(supabase.auth, descriptors);
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  if (user.app_metadata.role !== "admin") return new Response("Forbidden", { status: 403 });
  return Response.json(await deleteAdminData());
}
