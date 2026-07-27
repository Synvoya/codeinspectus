import AsyncStorage from "@react-native-async-storage/async-storage";
import * as SecureStore from "expo-secure-store";

export async function persistPreferences(theme: string, devicePushToken: string, accessToken: string) {
  await AsyncStorage.setItem("theme", theme);
  await AsyncStorage.setItem("push_token", devicePushToken);
  await SecureStore.setItemAsync("access_token", accessToken);
}
