import { useState, useCallback } from 'react';

interface ModalState<T = undefined> {
  isOpen: boolean;
  data: T | null;
}

export function useModalState<T = undefined>() {
  const [state, setState] = useState<ModalState<T>>({
    isOpen: false,
    data: null,
  });

  const open = useCallback((data?: T) => {
    setState({ isOpen: true, data: data ?? null });
  }, []);

  const close = useCallback(() => {
    setState({ isOpen: false, data: null });
  }, []);

  return {
    ...state,
    open,
    close,
  };
}
