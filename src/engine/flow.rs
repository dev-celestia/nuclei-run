//! Flow-control template support.
//!
//! Nuclei `flow:` templates gate request execution with a script (evaluated by
//! goja in the original). This engine supports the boolean subset of that DSL:
//! `http(n)`, `dns(n)`, `network(n)`/`tcp(n)`, `ssl(n)`, `code(n)` calls
//! combined with `&&`, `||`, `!` and parentheses (1-based indices, JS operator
//! precedence, short-circuit evaluation).
//!
//! Templates whose flow uses unsupported constructs (loops, functions,
//! `iterate`, `set`, `template.*`, other protocols) are reported as
//! unsupported and skipped instead of being executed without their gating
//! logic — running the blocks unconditionally produced false positives.

/// A parsed flow expression node. Protocol indices are stored 0-based.
#[derive(Debug, Clone, PartialEq)]
pub enum FlowNode {
    Http(usize),
    Dns(usize),
    Network(usize),
    Ssl(usize),
    Code(usize),
    Bool(bool),
    Not(Box<FlowNode>),
    And(Box<FlowNode>, Box<FlowNode>),
    Or(Box<FlowNode>, Box<FlowNode>),
}

/// Parse a flow expression. Returns `None` when the expression uses syntax
/// outside the supported boolean subset (the template must then be skipped).
pub fn parse_flow(expr: &str) -> Option<FlowNode> {
    let tokens = tokenize(expr)?;
    let mut parser = Parser { tokens, pos: 0 };
    let node = parser.parse_or()?;
    if parser.pos != parser.tokens.len() {
        return None; // trailing tokens -> unsupported syntax
    }
    Some(node)
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Call(String, usize), // protocol name, 0-based index
    Bool(bool),
    And,
    Or,
    Not,
    LParen,
    RParen,
}

fn tokenize(input: &str) -> Option<Vec<Token>> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        match c {
            '&' => {
                if i + 1 < chars.len() && chars[i + 1] == '&' {
                    tokens.push(Token::And);
                    i += 2;
                } else {
                    return None;
                }
            }
            '|' => {
                if i + 1 < chars.len() && chars[i + 1] == '|' {
                    tokens.push(Token::Or);
                    i += 2;
                } else {
                    return None;
                }
            }
            '!' => {
                if chars.get(i + 1) == Some(&'=') {
                    return None; // `!=` comparison — unsupported
                }
                tokens.push(Token::Not);
                i += 1;
            }
            '(' => {
                tokens.push(Token::LParen);
                i += 1;
            }
            ')' => {
                tokens.push(Token::RParen);
                i += 1;
            }
            _ if c.is_ascii_alphabetic() || c == '_' => {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let ident: String = chars[start..i].iter().collect();
                match ident.as_str() {
                    "true" => tokens.push(Token::Bool(true)),
                    "false" => tokens.push(Token::Bool(false)),
                    "http" | "dns" | "network" | "tcp" | "ssl" | "code" => {
                        // Expect `(N)` with a 1-based index.
                        if chars.get(i) != Some(&'(') {
                            return None;
                        }
                        i += 1;
                        let num_start = i;
                        while i < chars.len() && chars[i].is_ascii_digit() {
                            i += 1;
                        }
                        if num_start == i || chars.get(i) != Some(&')') {
                            return None;
                        }
                        let num: String = chars[num_start..i].iter().collect();
                        i += 1;
                        let idx: usize = num.parse().ok()?;
                        if idx == 0 {
                            return None; // nuclei flow indices are 1-based
                        }
                        tokens.push(Token::Call(ident.to_string(), idx - 1));
                    }
                    _ => return None, // unknown identifier -> unsupported
                }
            }
            _ => return None, // numbers, strings, operators, etc. -> unsupported
        }
    }

    Some(tokens)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    /// or_expr := and_expr ('||' and_expr)*
    fn parse_or(&mut self) -> Option<FlowNode> {
        let mut left = self.parse_and()?;
        while self.peek() == Some(&Token::Or) {
            self.advance();
            let right = self.parse_and()?;
            left = FlowNode::Or(Box::new(left), Box::new(right));
        }
        Some(left)
    }

    /// and_expr := unary ('&&' unary)*
    fn parse_and(&mut self) -> Option<FlowNode> {
        let mut left = self.parse_unary()?;
        while self.peek() == Some(&Token::And) {
            self.advance();
            let right = self.parse_unary()?;
            left = FlowNode::And(Box::new(left), Box::new(right));
        }
        Some(left)
    }

    /// unary := '!' unary | atom
    fn parse_unary(&mut self) -> Option<FlowNode> {
        if self.peek() == Some(&Token::Not) {
            self.advance();
            let node = self.parse_unary()?;
            return Some(FlowNode::Not(Box::new(node)));
        }
        self.parse_atom()
    }

    /// atom := '(' or_expr ')' | call | bool
    fn parse_atom(&mut self) -> Option<FlowNode> {
        match self.advance()? {
            Token::LParen => {
                let node = self.parse_or()?;
                if self.advance()? != Token::RParen {
                    return None;
                }
                Some(node)
            }
            Token::Call(name, idx) => Some(match name.as_str() {
                "http" => FlowNode::Http(idx),
                "dns" => FlowNode::Dns(idx),
                "network" | "tcp" => FlowNode::Network(idx),
                "ssl" => FlowNode::Ssl(idx),
                "code" => FlowNode::Code(idx),
                _ => return None,
            }),
            Token::Bool(b) => Some(FlowNode::Bool(b)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_and() {
        let node = parse_flow("http(1) && http(2)").unwrap();
        assert_eq!(
            node,
            FlowNode::And(Box::new(FlowNode::Http(0)), Box::new(FlowNode::Http(1)))
        );
    }

    #[test]
    fn test_parse_chain() {
        let node = parse_flow("http(1) && http(2) && http(3)").unwrap();
        assert!(matches!(node, FlowNode::And(_, _)));
    }

    #[test]
    fn test_parse_or_precedence() {
        // http(1) || http(2) && http(3)  ==  http(1) || (http(2) && http(3))
        let node = parse_flow("http(1) || http(2) && http(3)").unwrap();
        assert_eq!(
            node,
            FlowNode::Or(
                Box::new(FlowNode::Http(0)),
                Box::new(FlowNode::And(
                    Box::new(FlowNode::Http(1)),
                    Box::new(FlowNode::Http(2))
                ))
            )
        );
    }

    #[test]
    fn test_parse_parentheses_and_not() {
        let node = parse_flow("(http(1) && http(2)) || !http(3)").unwrap();
        assert!(matches!(node, FlowNode::Or(_, _)));
    }

    #[test]
    fn test_parse_mixed_protocols() {
        let node = parse_flow("dns(1) && ssl(1)").unwrap();
        assert_eq!(
            node,
            FlowNode::And(Box::new(FlowNode::Dns(0)), Box::new(FlowNode::Ssl(0)))
        );
    }

    #[test]
    fn test_reject_unsupported_constructs() {
        assert!(parse_flow("iterate(template.endpoints)").is_none());
        assert!(parse_flow("set(\"a\", 1)").is_none());
        assert!(parse_flow("javascript() && http(1)").is_none());
        assert!(parse_flow("http(0)").is_none());
        assert!(parse_flow("status_code == 200").is_none());
        assert!(parse_flow("let x = http(1)").is_none());
    }
}
