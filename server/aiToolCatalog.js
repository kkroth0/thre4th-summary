// Package and repository identities are stronger evidence than a generic "AI" keyword.
// Discovery rules supplement this seed catalog for newly disclosed components.
const groups = {
    'LLMs e inferência': [
        ['Ollama','ollama/ollama','ollama'], ['vLLM','vllm-project/vllm','vllm'], ['llama.cpp','ggml-org/llama.cpp','llama-cpp-python'],
        ['LocalAI','mudler/LocalAI','localai'], ['SGLang','sgl-project/sglang','sglang'], ['LMDeploy','internlm/lmdeploy','lmdeploy'],
        ['TGI','huggingface/text-generation-inference','text-generation-inference'], ['TensorRT-LLM','NVIDIA/TensorRT-LLM','tensorrt-llm'],
        ['BentoML','bentoml/BentoML','bentoml'], ['Xinference','xorbitsai/inference','xinference'], ['Ray Serve','ray-project/ray','ray'],
    ],
    'Interfaces e plataformas': [
        ['Open WebUI','open-webui/open-webui','open-webui'], ['LibreChat','danny-avila/LibreChat','librechat'], ['AnythingLLM','Mintplex-Labs/anything-llm','anythingllm'],
        ['Dify','langgenius/dify','dify'], ['Flowise','FlowiseAI/Flowise','flowise'], ['Langflow','langflow-ai/langflow','langflow'],
        ['LobeChat','lobehub/lobe-chat','@lobehub/chat'], ['Jan','menloresearch/jan'], ['KoboldCpp','LostRuins/koboldcpp','koboldcpp'],
        ['text-generation-webui','oobabooga/text-generation-webui','text-generation-webui'], ['ComfyUI','comfyanonymous/ComfyUI','comfyui'],
        ['AUTOMATIC1111','AUTOMATIC1111/stable-diffusion-webui','stable-diffusion-webui'], ['InvokeAI','invoke-ai/InvokeAI','invokeai'],
        ['Fooocus','lllyasviel/Fooocus','fooocus'], ['Gradio','gradio-app/gradio','gradio'], ['Streamlit','streamlit/streamlit','streamlit'],
    ],
    'Agentes e orquestração': [
        ['LangChain','langchain-ai/langchain','langchain','langchain-core','langchain-community','langchain-experimental'],
        ['LangGraph','langchain-ai/langgraph','langgraph','langgraph-checkpoint','langgraph-api'],
        ['LlamaIndex','run-llama/llama_index','llama-index','llama-index-core'], ['AutoGen','microsoft/autogen','autogen-agentchat','autogen-core','pyautogen'],
        ['CrewAI','crewAIInc/crewAI','crewai'], ['Semantic Kernel','microsoft/semantic-kernel','semantic-kernel'],
        ['Haystack','deepset-ai/haystack','haystack-ai','farm-haystack'], ['AutoGPT','Significant-Gravitas/AutoGPT','autogpt'],
        ['OpenHands','All-Hands-AI/OpenHands','openhands'], ['OpenAI Agents SDK','openai/openai-agents-python','openai-agents','@openai/agents'],
        ['Pydantic AI','pydantic/pydantic-ai','pydantic-ai'], ['smolagents','huggingface/smolagents','smolagents'],
        ['Agno','agno-agi/agno','agno'], ['Mastra','mastra-ai/mastra','@mastra/core'], ['n8n','n8n-io/n8n','n8n'],
    ],
    'MCP e integrações': [
        ['GitHub MCP Server','github/github-mcp-server','github.com/github/github-mcp-server'], ['Playwright MCP','microsoft/playwright-mcp','@playwright/mcp'],
        ['Browser Use','browser-use/browser-use','browser-use'], ['Crawl4AI','unclecode/crawl4ai','crawl4ai'], ['Firecrawl','firecrawl/firecrawl','firecrawl-py','@mendable/firecrawl-js'],
        ['Context7 MCP','upstash/context7','@upstash/context7-mcp'], ['Chrome DevTools MCP','ChromeDevTools/chrome-devtools-mcp','chrome-devtools-mcp'],
        ['MCP Python SDK','modelcontextprotocol/python-sdk','mcp'], ['MCP TypeScript SDK','modelcontextprotocol/typescript-sdk','@modelcontextprotocol/sdk'],
        ['MCP servidores de referência','modelcontextprotocol/servers','@modelcontextprotocol/server-filesystem','@modelcontextprotocol/server-git','@modelcontextprotocol/server-fetch','@modelcontextprotocol/server-sqlite','mcp-server-git','mcp-server-fetch'],
        ['MCP Inspector','modelcontextprotocol/inspector','@modelcontextprotocol/inspector'], ['FastMCP','jlowin/fastmcp','fastmcp'],
        ['MCP Go','mark3labs/mcp-go','github.com/mark3labs/mcp-go'], ['MCP Java SDK','modelcontextprotocol/java-sdk','io.modelcontextprotocol.sdk:mcp'],
        ['MCP Rust SDK','modelcontextprotocol/rust-sdk','rmcp'], ['MCP C# SDK','modelcontextprotocol/csharp-sdk','ModelContextProtocol'],
        ['MCP Supergateway','supercorp-ai/supergateway','supergateway'], ['MCP Proxy','sparfenyuk/mcp-proxy','mcp-proxy'],
        ['MCP Remote','geelen/mcp-remote','mcp-remote'], ['MCP ContextForge','IBM/mcp-context-forge','mcp-contextforge-gateway'],
    ],
    'RAG, busca e dados': [
        ['Chroma','chroma-core/chroma','chromadb'], ['Qdrant','qdrant/qdrant','qdrant-client'], ['Milvus','milvus-io/milvus','pymilvus'],
        ['Weaviate','weaviate/weaviate','weaviate-client'], ['LanceDB','lancedb/lancedb','lancedb'], ['FAISS','facebookresearch/faiss','faiss-cpu','faiss-gpu'],
        ['RAGFlow','infiniflow/ragflow','ragflow'], ['RAGAnything','HKUDS/RAG-Anything','raganything'], ['LightRAG','HKUDS/LightRAG','lightrag-hku'],
        ['Unstructured','Unstructured-IO/unstructured','unstructured'], ['Docling','docling-project/docling','docling'],
        ['Vanna','vanna-ai/vanna','vanna'], ['DB-GPT','eosphoros-ai/DB-GPT','dbgpt'], ['Embedchain','mem0ai/mem0','embedchain','mem0ai'],
    ],
    'Modelos, treinamento e MLOps': [
        ['PyTorch','pytorch/pytorch','torch'], ['TensorFlow','tensorflow/tensorflow','tensorflow','tensorflow-cpu'], ['Keras','keras-team/keras','keras'],
        ['Transformers','huggingface/transformers','transformers'], ['Diffusers','huggingface/diffusers','diffusers'],
        ['Datasets','huggingface/datasets','datasets'], ['Hugging Face Hub','huggingface/huggingface_hub','huggingface-hub'],
        ['Safetensors','huggingface/safetensors','safetensors'], ['Tokenizers','huggingface/tokenizers','tokenizers'], ['PEFT','huggingface/peft','peft'],
        ['Accelerate','huggingface/accelerate','accelerate'], ['TRL','huggingface/trl','trl'], ['Sentence Transformers','UKPLab/sentence-transformers','sentence-transformers'],
        ['ONNX','onnx/onnx','onnx'], ['ONNX Runtime','microsoft/onnxruntime','onnxruntime','onnxruntime-gpu'], ['MLflow','mlflow/mlflow','mlflow'],
        ['Kubeflow','kubeflow/kubeflow','kubeflow'], ['ClearML','clearml/clearml','clearml'], ['BentoML MLServer','SeldonIO/MLServer','mlserver'],
        ['Seldon Core','SeldonIO/seldon-core','seldon-core'], ['KServe','kserve/kserve','kserve'], ['Triton Server','triton-inference-server/server','tritonserver'],
        ['DeepSpeed','deepspeedai/DeepSpeed','deepspeed'], ['JAX','jax-ml/jax','jax'], ['Scikit-learn','scikit-learn/scikit-learn','scikit-learn'],
        ['XGBoost','dmlc/xgboost','xgboost'], ['H2O','h2oai/h2o-3','h2o'], ['Jupyter','jupyter-server/jupyter_server','jupyter-server','notebook','jupyterlab'],
        ['DVC','iterative/dvc','dvc'], ['Dask','dask/distributed','distributed'], ['Horovod','horovod/horovod','horovod'],
    ],
    'Gateways, SDKs e observabilidade': [
        ['LiteLLM','BerriAI/litellm','litellm'], ['Portkey','Portkey-AI/gateway','portkey-ai','@portkey-ai/gateway'],
        ['OpenAI SDK','openai/openai-python','openai'], ['Anthropic SDK','anthropics/anthropic-sdk-python','anthropic','@anthropic-ai/sdk'],
        ['Google Gen AI SDK','googleapis/python-genai','google-genai','@google/genai'], ['Vercel AI SDK','vercel/ai','ai','@ai-sdk/provider'],
        ['Langfuse','langfuse/langfuse','langfuse'], ['LangSmith','langchain-ai/langsmith-sdk','langsmith'],
        ['Phoenix','Arize-ai/phoenix','arize-phoenix'], ['Opik','comet-ml/opik','opik'], ['W&B','wandb/wandb','wandb'],
        ['NeMo Guardrails','NVIDIA/NeMo-Guardrails','nemoguardrails'], ['Guardrails AI','guardrails-ai/guardrails','guardrails-ai'],
    ],
    'Assistentes e ferramentas de código': [
        ['Cursor','','cursor'], ['Windsurf','','windsurf','codeium'], ['GitHub Copilot','','github-copilot'],
        ['Claude Code','anthropics/claude-code','@anthropic-ai/claude-code'], ['Codex CLI','openai/codex','@openai/codex'],
        ['Gemini CLI','google-gemini/gemini-cli','@google/gemini-cli'], ['Cline','cline/cline','cline'], ['Roo Code','RooCodeInc/Roo-Code','roo-code'],
        ['Continue','continuedev/continue','@continuedev/cli'], ['Aider','Aider-AI/aider','aider-chat'], ['OpenCode','sst/opencode','opencode-ai'],
        ['Tabby','TabbyML/tabby','tabbyml'], ['Open Interpreter','OpenInterpreter/open-interpreter','open-interpreter'],
    ],
    'Serviços e assistentes de IA': [
        ['ChatGPT','','chatgpt'], ['Claude','','claude'], ['Google Gemini','','gemini'], ['Microsoft Copilot','','microsoft-copilot'],
        ['Perplexity','','perplexity'], ['DeepSeek','','deepseek'], ['Grok','','grok'], ['Mistral AI','','mistralai'],
        ['LM Studio','','lm-studio'], ['Amazon Bedrock','','amazon-bedrock'], ['Amazon SageMaker','','sagemaker'],
        ['Azure AI','','azure-ai'], ['Google Vertex AI','','vertex-ai'], ['IBM watsonx','','watsonx'],
        ['Databricks AI','','databricks-ai'], ['Snowflake Cortex','','snowflake-cortex'], ['JetBrains AI Assistant','','jetbrains-ai-assistant'],
    ],
};
export const AI_TOOL_CATALOG = Object.entries(groups).flatMap(([category, entries]) => entries.map(([name, repo, ...packages]) => ({ name, category, repo: repo.toLowerCase(), packages })));
export const AI_CATEGORIES = Object.keys(groups);
const normalize = v => String(v || '').toLowerCase().replace(/[_\s]+/g, '-');
const patterns = new Map();
const bounded = (text, term) => {
    if (term.length < 3) return false;
    if (!patterns.has(term)) patterns.set(term, new RegExp('(^|[^a-z0-9])' + term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/[-_ ]/g, '[-_ ]') + '([^a-z0-9]|$)', 'i'));
    return patterns.get(term).test(text);
};
// A single cheap prefilter precedes strict identity checks. A large FTS OR
// intersection paged the production corpus heavily; date-index streaming keeps
// the read bounded and avoids loading a second full-text posting list.
const candidateTerms = [...new Set([...AI_TOOL_CATALOG.flatMap(t => [t.name, ...t.packages, t.repo]).filter(t => t.length >= 3 && !['Continue','Jan','datasets','notebook','distributed','accelerate'].includes(t)), 'MCP', 'LLM', 'large language', 'generative AI', 'AI agent', 'model inference', 'retrieval augmented'])];
const candidatePattern = new RegExp(candidateTerms.sort((a, b) => b.length - a.length).map(t => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/[-_ ]/g, '[-_ ]')).join('|'), 'i');
export const possibleAiTool = row => candidatePattern.test(`${row.product || ''} ${row.description || ''} ${row.references_json || ''}`);
function affectedSubject(value) {
    const intro = value.trim().slice(0, 700)
        .replace(/^.*?\bvulnerability (?:was (?:found|identified|determined|discovered) )?in\s+/i, '')
        .replace(/^A security flaw has been discovered in\s+/i, '').replace(/^The\s+/i, '');
    const subject = intro.split(/\s+(?:is|are|allows?|contains?|has|through|up to|before|prior to|versions?|suffers|via|using)\b|\.\s/i)[0].trim();
    return subject.length >= 3 && subject.length <= 200 ? subject : '';
}
export function classifyAiTool({ packages = [], repository = '', text = '', summary = '', references = [], product = '' } = {}) {
    const repo = repository.toLowerCase().replace(/^https?:\/\/github.com\//, '').replace(/\/$/, '');
    const identities = packages.filter(p => p && (typeof p === 'string' || p.name)).map(p => normalize(typeof p === 'string' ? p : p.name));
    const prose = `${product} ${text}`.slice(0, 30000);
    const links = references.map(r => typeof r === 'string' ? r : r.url).filter(Boolean);
    const exact = AI_TOOL_CATALOG.filter(tool => identities.some(p => tool.packages.some(t => normalize(t) === p) && (p !== 'ai' || packages.some(pkg => pkg?.name === 'ai' && pkg.ecosystem === 'npm')))
        || (tool.repo && (repo === tool.repo || links.some(url => url.toLowerCase().startsWith(`https://github.com/${tool.repo}/`)))));
    if (exact.length) return exact.map(tool => ({ name: tool.name, category: tool.category, evidence: 'catalog' }));
    const ambiguous = ['Jan', 'AI SDK', 'Cursor', 'Datasets', 'Accelerate', 'Keras', 'JAX', 'H2O', 'Jupyter', 'Continue', 'Claude', 'Grok', 'Transformers', 'Diffusers', 'Phoenix', 'Codex CLI'];
    const matches = AI_TOOL_CATALOG.filter(tool => (!packages.length && bounded(prose.slice(0, 4000), tool.name) && !ambiguous.includes(tool.name))
        || normalize(product) === normalize(tool.name)
        || tool.packages.some(p => p.length > 4 && normalize(product) === normalize(p)));
    if (matches.length) {
        const direct = matches.filter(tool => normalize(product) === normalize(tool.name) || tool.packages.some(p => normalize(product) === normalize(p)));
        if (direct.length) return direct.map(tool => ({ name: tool.name, category: tool.category, evidence: 'catalog' }));
        const subject = affectedSubject(prose), named = matches.filter(tool => bounded(subject, tool.name));
        if (subject && named.length && !/\b(?:reported|discovered by|credits?|researcher)\b/i.test(subject)) {
            const canonical = named.find(tool => normalize(subject) === normalize(tool.name));
            return canonical ? [{ name: canonical.name, category: canonical.category, evidence: 'catalog' }]
                : [{ name: subject, category: /\b(?:plugin|extension|assistant|chatbot)\b/i.test(subject) ? 'Interfaces e plataformas' : named[0].category, evidence: 'discovery', relatedTools: named.map(t => t.name) }];
        }
        // A brand in credits or integrations must not turn a third-party
        // plugin vulnerability into a vulnerability of ChatGPT/Claude itself.
        const specific = matches.filter(tool => tool.category !== 'Serviços e assistentes de IA');
        if (specific.length) return specific.map(tool => ({ name: tool.name, category: tool.category, evidence: 'catalog' }));
    }
    // MCP must mean Model Context Protocol, not an unrelated acronym/product.
    const heading = `${summary} ${product} ${identities.join(' ')}`;
    const mcp = /model context protocol|\bmcp[- _](?:server|sdk|proxy|gateway|inspector|client|tool)|(?:^|[-/@])mcp(?:$|[-/_])|@modelcontextprotocol\//i.test(heading)
        || /(?:is|provides?|implements?) (?:an? |the )?[^.\n]{0,100}Model Context Protocol/i.test(prose.slice(0, 1500));
    const ai = /\b(?:LLM|AI)[- ](?:agent|tool|framework|platform|inference|gateway)|large language model|retrieval[- ]augmented generation|diffusion model/i.test(heading)
        || /(?:is|provides?|implements?) (?:an? |the )?[^.\n]{0,100}(?:large language models?|LLM[- ](?:agent|tool|framework)|generative AI|AI agents?|retrieval[- ]augmented generation)/i.test(prose.slice(0, 1500));
    if (!mcp && !ai) return [];
    const name = packages[0]?.name || (typeof packages[0] === 'string' ? packages[0] : '') || product || repo || (mcp ? 'Componente MCP' : 'Componente de IA');
    return [{ name: String(name).slice(0, 180), category: mcp ? 'MCP e integrações' : /agent/i.test(prose) ? 'Agentes e orquestração' : 'Outros componentes de IA', evidence: 'discovery' }];
}
