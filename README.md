# kube-netdiag

根拠付き・読み取り専用の Kubernetes 診断 CLI。初期プロトタイプです。

## ローカル実行

Go 1.24 以上を使用します。サンプル実行にはクラスタ、GPU、Docker は不要です。

```sh
go mod download
go run . --file examples/denied.json --source client --destination backend --port 80
go run . --file examples/denied.json --source client --destination backend --port 80 --output json
make test
make build
```

## 実クラスタから読み取り

`kubectl` と設定済みの current-context が必要です。

```sh
kubectl config current-context
./bin/kube-netdiag --live --namespace default --source client --destination backend --port 80 --output json
```

API 読み取りに失敗した場合は `unknown` finding と取得制限を返します。自動でクラスタを変更しません。`kubectl` は kubeconfig の認証プラグインを利用する場合があります。

## 結果と制限

- `confirmed`: 入力に存在する観測事実。
- `predicted`: 入力が対象を網羅するという前提での静的判定。
- `unknown`: 対象・データ不足、未対応条件。
- 終了コード 0 は診断処理完了を意味し、正常性の保証ではありません。入力・引数エラーは 1。
- `--output text|json|markdown`。現段階の Markdown はプレーンテキストと同じ内容です。
- Secret の値や任意の Event/Condition メッセージは出力しません。出力のリソース名やラベルに機密を含めないでください。
- スナップショットは複数 YAML ドキュメント、単一オブジェクト、Kubernetes List 形式に対応。入力は最大 32 MiB を想定。
- 各診断の具体的な未評価項目は `limitations` に出力します。
- 実クラスタ、実 GPU、Linux での実行検証は別途必要です。

詳細は [開発・権限メモ](docs/design.md) を参照してください。
