// src/lib/auth.js
import { api } from "@/api";

export async function login({ email, password }) {
  await api.login({ email, password });
}

export async function signup({ email, password, name, company }) {
  await api.signup({ email, password, name, company });
}

export async function logout() {
  await api.logout();
}

export async function me() {
  try {
    return await api.me();
  } catch {
    return null;
  }
}
