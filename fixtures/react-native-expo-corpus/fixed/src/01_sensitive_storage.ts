import * as SecureStore from "expo-secure-store";

const accessToken = "CI_RN_EXPO_REDACTION_SENTINEL";

export async function persistSession(): Promise<void> {
  await SecureStore.setItemAsync("access_token", accessToken);
}
