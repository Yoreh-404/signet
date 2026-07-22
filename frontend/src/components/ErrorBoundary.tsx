import { Component, ErrorInfo, ReactNode } from "react";

type Props = {
  children: ReactNode;
};

type State = {
  failed: boolean;
};

export class ErrorBoundary extends Component<Props, State> {
  state: State = { failed: false };

  static getDerivedStateFromError(): State {
    return { failed: true };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("The administration console failed to render", error, info);
  }

  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <main className="fatal-error" role="alert">
        <div>
          <span>Signet</span>
          <h1>页面暂时无法显示</h1>
          <p>The page could not be rendered. Reload to restore the administration console.</p>
          <button type="button" onClick={() => window.location.reload()}>重新加载 / Reload</button>
        </div>
      </main>
    );
  }
}
