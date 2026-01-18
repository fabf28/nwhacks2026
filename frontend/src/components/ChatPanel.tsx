import React, { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { MessageCircle, X, Send, Loader2, Bot, User } from 'lucide-react';

interface ChatMessage {
    role: 'user' | 'model';
    content: string;
}

interface ChatPanelProps {
    scanContext: any;
    isOpen: boolean;
    onClose: () => void;
}

const ChatPanel: React.FC<ChatPanelProps> = ({ scanContext, isOpen, onClose }) => {
    const [messages, setMessages] = useState<ChatMessage[]>([]);
    const [input, setInput] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const messagesEndRef = useRef<HTMLDivElement>(null);

    const scrollToBottom = () => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    };

    useEffect(() => {
        scrollToBottom();
    }, [messages]);

    // Add welcome message when opening
    useEffect(() => {
        if (isOpen && messages.length === 0) {
            setMessages([{
                role: 'model',
                content: `👋 Hi! I'm your AI security assistant. I've analyzed the scan results for **${scanContext?.url || 'this website'}**.\n\nYou can ask me:\n- What vulnerabilities were found?\n- How do I fix [specific issue]?\n- Is this website safe?\n- What should I prioritize?`
            }]);
        }
    }, [isOpen, scanContext]);

    const sendMessage = async () => {
        if (!input.trim() || isLoading) return;

        const userMessage = input.trim();
        setInput('');
        setMessages(prev => [...prev, { role: 'user', content: userMessage }]);
        setIsLoading(true);

        try {
            const response = await fetch('http://localhost:3001/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: userMessage,
                    scanContext,
                    conversationHistory: messages.filter(m => m.role !== 'model' || !m.content.startsWith('👋')),
                }),
            });

            const data = await response.json();

            if (data.response) {
                setMessages(prev => [...prev, { role: 'model', content: data.response }]);
            } else {
                throw new Error('No response received');
            }
        } catch (error: any) {
            setMessages(prev => [...prev, {
                role: 'model',
                content: `Sorry, I encountered an error: ${error.message}. Please try again.`
            }]);
        } finally {
            setIsLoading(false);
        }
    };

    const handleKeyDown = (e: React.KeyboardEvent) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    };

    // Simple markdown renderer for bold and code
    const renderMessage = (content: string) => {
        return content
            .split(/(\*\*.*?\*\*|`.*?`)/g)
            .map((part, i) => {
                if (part.startsWith('**') && part.endsWith('**')) {
                    return <strong key={i}>{part.slice(2, -2)}</strong>;
                }
                if (part.startsWith('`') && part.endsWith('`')) {
                    return <code key={i} style={{
                        background: 'rgba(0,0,0,0.3)',
                        padding: '2px 6px',
                        borderRadius: '4px',
                        fontSize: '0.9em'
                    }}>{part.slice(1, -1)}</code>;
                }
                return part;
            });
    };

    return (
        <AnimatePresence>
            {isOpen && (
                <>
                    {/* Backdrop */}
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        onClick={onClose}
                        style={{
                            position: 'fixed',
                            inset: 0,
                            background: 'rgba(0,0,0,0.5)',
                            zIndex: 998,
                        }}
                    />

                    {/* Chat Panel */}
                    <motion.div
                        initial={{ x: '100%' }}
                        animate={{ x: 0 }}
                        exit={{ x: '100%' }}
                        transition={{ type: 'spring', damping: 25, stiffness: 200 }}
                        style={{
                            position: 'fixed',
                            top: 0,
                            right: 0,
                            bottom: 0,
                            width: '420px',
                            maxWidth: '100vw',
                            background: 'linear-gradient(180deg, rgba(15,15,30,0.98) 0%, rgba(10,10,20,0.98) 100%)',
                            borderLeft: '1px solid var(--glass-border)',
                            display: 'flex',
                            flexDirection: 'column',
                            zIndex: 999,
                        }}
                    >
                        {/* Header */}
                        <div style={{
                            padding: '20px',
                            borderBottom: '1px solid var(--glass-border)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                        }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                <Bot size={24} color="var(--primary)" />
                                <div>
                                    <h3 style={{ margin: 0, fontSize: '1.1rem' }}>AI Security Assistant</h3>
                                    <p style={{ margin: 0, fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                                        Powered by Gemini
                                    </p>
                                </div>
                            </div>
                            <button
                                onClick={onClose}
                                style={{
                                    background: 'transparent',
                                    border: 'none',
                                    color: 'var(--text-muted)',
                                    cursor: 'pointer',
                                    padding: '8px',
                                }}
                            >
                                <X size={20} />
                            </button>
                        </div>

                        {/* Messages */}
                        <div style={{
                            flex: 1,
                            overflowY: 'auto',
                            padding: '20px',
                            display: 'flex',
                            flexDirection: 'column',
                            gap: '16px',
                        }}>
                            {messages.map((msg, i) => (
                                <div
                                    key={i}
                                    style={{
                                        display: 'flex',
                                        gap: '12px',
                                        alignItems: 'flex-start',
                                        flexDirection: msg.role === 'user' ? 'row-reverse' : 'row',
                                    }}
                                >
                                    <div style={{
                                        width: '32px',
                                        height: '32px',
                                        borderRadius: '50%',
                                        background: msg.role === 'user' ? 'var(--primary)' : 'rgba(255,255,255,0.1)',
                                        display: 'flex',
                                        alignItems: 'center',
                                        justifyContent: 'center',
                                        flexShrink: 0,
                                    }}>
                                        {msg.role === 'user' ? <User size={16} /> : <Bot size={16} color="var(--primary)" />}
                                    </div>
                                    <div style={{
                                        background: msg.role === 'user' ? 'var(--primary)' : 'rgba(255,255,255,0.05)',
                                        padding: '12px 16px',
                                        borderRadius: '16px',
                                        borderTopRightRadius: msg.role === 'user' ? '4px' : '16px',
                                        borderTopLeftRadius: msg.role === 'user' ? '16px' : '4px',
                                        maxWidth: '80%',
                                        lineHeight: 1.5,
                                        whiteSpace: 'pre-wrap',
                                    }}>
                                        {renderMessage(msg.content)}
                                    </div>
                                </div>
                            ))}

                            {isLoading && (
                                <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                                    <div style={{
                                        width: '32px',
                                        height: '32px',
                                        borderRadius: '50%',
                                        background: 'rgba(255,255,255,0.1)',
                                        display: 'flex',
                                        alignItems: 'center',
                                        justifyContent: 'center',
                                    }}>
                                        <Bot size={16} color="var(--primary)" />
                                    </div>
                                    <div style={{
                                        background: 'rgba(255,255,255,0.05)',
                                        padding: '12px 16px',
                                        borderRadius: '16px',
                                        borderTopLeftRadius: '4px',
                                    }}>
                                        <Loader2 size={16} className="animate-spin" style={{ color: 'var(--primary)' }} />
                                    </div>
                                </div>
                            )}

                            <div ref={messagesEndRef} />
                        </div>

                        {/* Input */}
                        <div style={{
                            padding: '20px',
                            borderTop: '1px solid var(--glass-border)',
                        }}>
                            <div style={{
                                display: 'flex',
                                gap: '12px',
                                background: 'rgba(255,255,255,0.05)',
                                borderRadius: '24px',
                                padding: '8px 16px',
                                alignItems: 'center',
                            }}>
                                <input
                                    type="text"
                                    value={input}
                                    onChange={(e) => setInput(e.target.value)}
                                    onKeyDown={handleKeyDown}
                                    placeholder="Ask about the security scan..."
                                    style={{
                                        flex: 1,
                                        background: 'transparent',
                                        border: 'none',
                                        outline: 'none',
                                        color: 'white',
                                        fontSize: '0.95rem',
                                    }}
                                />
                                <button
                                    onClick={sendMessage}
                                    disabled={!input.trim() || isLoading}
                                    style={{
                                        background: input.trim() ? 'var(--primary)' : 'rgba(255,255,255,0.1)',
                                        border: 'none',
                                        borderRadius: '50%',
                                        width: '36px',
                                        height: '36px',
                                        display: 'flex',
                                        alignItems: 'center',
                                        justifyContent: 'center',
                                        cursor: input.trim() ? 'pointer' : 'not-allowed',
                                        transition: 'all 0.2s',
                                    }}
                                >
                                    <Send size={16} color={input.trim() ? 'black' : 'var(--text-muted)'} />
                                </button>
                            </div>
                        </div>
                    </motion.div>
                </>
            )}
        </AnimatePresence>
    );
};

export default ChatPanel;
