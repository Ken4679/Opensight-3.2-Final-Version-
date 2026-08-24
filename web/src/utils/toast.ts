import { ToastMessage, ToastType } from "../types";

type Listener = (toasts: ToastMessage[]) => void;

class ToastManager {
  private toasts: ToastMessage[] = [];
  private listeners: Listener[] = [];

  subscribe(listener: Listener) {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter((l) => l !== listener);
    };
  }

  private notify() {
    this.listeners.forEach((listener) => listener([...this.toasts]));
  }

  show(type: ToastType, title: string, description?: string) {
    const id = Math.random().toString(36).substring(2, 9);
    const toast: ToastMessage = { id, type, title, description };
    this.toasts.push(toast);
    this.notify();

    setTimeout(() => {
      this.dismiss(id);
    }, 4000);
  }

  success(title: string, description?: string) {
    this.show("success", title, description);
  }

  error(title: string, description?: string) {
    this.show("error", title, description);
  }

  info(title: string, description?: string) {
    this.show("info", title, description);
  }

  warning(title: string, description?: string) {
    this.show("warning", title, description);
  }

  dismiss(id: string) {
    this.toasts = this.toasts.filter((t) => t.id !== id);
    this.notify();
  }
}

export const toast = new ToastManager();
