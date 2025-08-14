# SafeTrace: Cryptology-Based Contact Tracing Framework

A post-quantum ready contact tracing system built with Python's standard library, designed for secure, privacy-preserving contact tracing with cryptographic guarantees.

## 🚀 Features

### Core Functionality
- **Cryptographic User IDs**: 256-bit random user identifiers for collision resistance
- **Secure Contact Logging**: SHA-256 hashed contact events with timestamps
- **Anonymous Alert System**: Privacy-preserving exposure notifications
- **Tamper-Proof Logging**: Immutable contact records with integrity verification

### Security Features
- **Privacy Protection**: No raw user IDs stored in contact logs
- **Replay Attack Prevention**: Unique session keys and alert identifiers
- **Time-Window Filtering**: Configurable contact tracing windows
- **Data Integrity**: Cryptographic verification of contact records

### Post-Quantum Ready Design
- **XMSS Integration Ready**: Modular design for stateful hash-based signatures
- **Threshold Consensus**: Extensible for multi-party alert verification
- **Zero-Knowledge Proofs**: Framework ready for privacy-preserving computations
- **Lattice-Based Cryptography**: Compatible with quantum-resistant algorithms

## 🛠 Tech Stack

- **Language**: Python 3.7+
- **Libraries**: Standard library only (hashlib, datetime, random, json, typing)
- **Deployment**: Vercel-compatible (no virtual environment required)

## 📁 Project Structure

```
SafeTrace/
├── index.py          # Main implementation file
├── README.md         # This documentation
└── .gitignore        # Git ignore file
```

## 🚀 Quick Start

### Local Development
```bash
# Clone the repository
git clone <repository-url>
cd SafeTrace

# Run the simulation
python index.py
```

### Vercel Deployment
1. Push your code to GitHub
2. Connect your repository to Vercel
3. Deploy automatically - no configuration needed!

## 🔧 API Reference

### SafeTrace Class

#### `generate_user_id() -> str`
Generates a unique 256-bit random user identifier.

#### `log_contact(user_a: str, user_b: str) -> str`
Logs a contact event between two users and returns the contact hash.

#### `check_positive_case(user_id: str, contact_window_hours: int = 14) -> List[Dict]`
Checks for potential exposures when a user tests positive.

#### `get_contact_statistics() -> Dict`
Returns anonymous statistics about contact patterns.

#### `verify_contact_integrity(contact_hash: str) -> bool`
Verifies the integrity of a contact hash.

## 🔒 Security Architecture

### Contact Hashing
```python
# Contact data is hashed using SHA-256
contact_data = f"{sorted_user_a}-{sorted_user_b}-{timestamp}-{session_key}"
contact_hash = hashlib.sha256(contact_data.encode()).hexdigest()
```

### Privacy Protection
- User IDs are never stored in raw form
- Contact logs contain only cryptographic hashes
- Alert generation is completely anonymous
- Session keys prevent correlation attacks

### Post-Quantum Extensions
The system is designed to integrate:
- **XMSS Signatures**: For contact proof verification
- **Threshold Consensus**: For multi-party alert verification
- **Zero-Knowledge Proofs**: For privacy-preserving contact discovery
- **Lattice-Based Commitments**: For additional privacy layers

## 📊 Simulation Output

The system includes a comprehensive simulation that demonstrates:
- User creation and management
- Contact event logging
- Positive case handling
- Anonymous alert generation
- Security feature verification

## 🔮 Future Enhancements

### Phase 1: XMSS Integration
- Implement stateful hash-based signatures
- Add contact proof verification
- Enhance tamper resistance

### Phase 2: Threshold Consensus
- Multi-party alert verification
- Distributed contact validation
- Byzantine fault tolerance

### Phase 3: Advanced Privacy
- Zero-knowledge proof integration
- Oblivious RAM for secure deletion
- Differential privacy for statistics

## 🚨 Important Notes

- **No External Dependencies**: Uses only Python standard library
- **Vercel Compatible**: Ready for serverless deployment
- **Privacy First**: Designed with privacy-by-default principles
- **Post-Quantum Ready**: Extensible for quantum-resistant cryptography

## 📄 License

This project is open source and available under the MIT License.

## 🤝 Contributing

Contributions are welcome! Please ensure all code follows the project's security and privacy standards.

---

**SafeTrace**: Secure, Privacy-Preserving Contact Tracing for the Quantum Age
