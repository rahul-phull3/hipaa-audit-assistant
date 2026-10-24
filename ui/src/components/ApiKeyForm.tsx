import { type FormEvent, useId, useState } from "react";

interface Props {
  hasKey: boolean;
  onSave: (key: string) => void;
  onForget: () => void;
}

export function ApiKeyForm({ hasKey, onSave, onForget }: Props) {
  const [value, setValue] = useState("");
  const inputId = useId();
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!value.trim()) return;
    onSave(value);
    setValue("");
  };
  return (
    <form className="key-form" onSubmit={submit}>
      <label htmlFor={inputId}>API key</label>
      <input
        id={inputId}
        type="password"
        autoComplete="off"
        spellCheck={false}
        value={value}
        onChange={(e) => setValue(e.currentTarget.value)}
        placeholder={hasKey ? "A key is saved for this tab" : "Paste the key here"}
      />
      <button type="submit" className="btn btn-primary" disabled={!value.trim()}>
        Save key
      </button>
      {hasKey ? (
        <button type="button" className="btn btn-quiet" onClick={onForget}>
          Forget key
        </button>
      ) : null}
    </form>
  );
}
