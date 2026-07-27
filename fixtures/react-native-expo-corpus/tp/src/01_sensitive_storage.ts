import AsyncStorage from "@react-native-async-storage/async-storage";

const accessToken = "CI_RN_EXPO_REDACTION_SENTINEL";

export async function persistSession(): Promise<void> {
  await AsyncStorage.setItem("access_token", accessToken);
}
