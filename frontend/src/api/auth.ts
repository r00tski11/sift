import client from "./client";
import type { TokenResponse, User } from "./types";

export async function login(
  email: string,
  password: string
): Promise<TokenResponse> {
  const response = await client.post<TokenResponse>("/auth/login", {
    email,
    password,
  });
  return response.data;
}

export async function register(
  email: string,
  username: string,
  password: string
): Promise<User> {
  const response = await client.post<User>("/auth/register", {
    email,
    username,
    password,
  });
  return response.data;
}

export async function refreshToken(
  refresh_token: string
): Promise<TokenResponse> {
  const response = await client.post<TokenResponse>("/auth/refresh", {
    refresh_token,
  });
  return response.data;
}

export async function getMe(): Promise<User> {
  const response = await client.get<User>("/auth/me");
  return response.data;
}
