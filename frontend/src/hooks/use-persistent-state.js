import { useCallback, useEffect, useRef, useState } from 'react';

const SYNC_EVENT = 'aegisfa-storage-sync';

function resolveInitialValue(initialValue) {
  return typeof initialValue === 'function' ? initialValue() : initialValue;
}

function readStoredValue(key, initialValue) {
  if (typeof window === 'undefined') {
    return resolveInitialValue(initialValue);
  }

  const raw = window.localStorage.getItem(key);
  if (raw == null) {
    return resolveInitialValue(initialValue);
  }

  try {
    return JSON.parse(raw);
  } catch {
    return resolveInitialValue(initialValue);
  }
}

export function usePersistentState(key, initialValue) {
  const [value, setValue] = useState(() => readStoredValue(key, initialValue));
  const valueRef = useRef(value);
  const instanceIdRef = useRef(`ps-${Math.random().toString(36).slice(2)}`);

  useEffect(() => {
    valueRef.current = value;
  }, [value]);

  const updateValue = useCallback((nextValue) => {
    const currentValue = valueRef.current;
    const resolvedValue = typeof nextValue === 'function' ? nextValue(currentValue) : nextValue;

    valueRef.current = resolvedValue;
    setValue(resolvedValue);

    if (typeof window !== 'undefined') {
      window.localStorage.setItem(key, JSON.stringify(resolvedValue));
      window.dispatchEvent(new CustomEvent(SYNC_EVENT, {
        detail: {
          key,
          value: resolvedValue,
          sourceId: instanceIdRef.current,
        },
      }));
    }
  }, [key]);

  useEffect(() => {
    const syncFromStorage = () => {
      setValue(readStoredValue(key, initialValue));
    };

    const handleStorage = (event) => {
      if (event.key === key) {
        syncFromStorage();
      }
    };

    const handleCustomSync = (event) => {
      const detail = event?.detail || {};
      if (detail.key === key && detail.sourceId !== instanceIdRef.current) {
        valueRef.current = detail.value;
        setValue(detail.value);
      }
    };

    window.addEventListener('storage', handleStorage);
    window.addEventListener(SYNC_EVENT, handleCustomSync);

    return () => {
      window.removeEventListener('storage', handleStorage);
      window.removeEventListener(SYNC_EVENT, handleCustomSync);
    };
  }, [key, initialValue]);

  return [value, updateValue];
}

export default usePersistentState;
