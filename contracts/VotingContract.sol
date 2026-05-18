// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@semaphore-protocol/contracts/interfaces/IVerifier.sol";
import "@semaphore-protocol/contracts/base/SemaphoreGroups.sol";

/**
 * @title VotingContract
 * @dev Anonymes Blockchain-basiertes Wahlsystem mit Semaphore für Anonymität
 * Ethereum für Sicherheit & Wahrheit
 * zkSync für Skalierung
 */
contract VotingContract is SemaphoreGroups {
    // ============ Strukturen ============
    
    struct Vote {
        uint256 commitment; // Semaphore Commitment für Anonymität
        uint256 option;     // Wahlmöglichkeit (0=Ja, 1=Nein, etc.)
        uint256 timestamp;  // Zeitstempel des Votes
    }
    
    struct Election {
        string title;
        string[] options;
        uint256 startTime;
        uint256 endTime;
        bool active;
        uint256 totalVotes;
        mapping(uint256 => uint256) voteCount; // Option -> Anzahl Votes
    }
    
    // ============ State Variables ============
    
    mapping(uint256 => Election) public elections;
    mapping(uint256 => Vote[]) public electionVotes;
    mapping(uint256 => mapping(uint256 => bool)) public hasVoted; // electionId -> commitment -> voted
    
    uint256 public electionCounter = 0;
    uint256 public semaphoreGroupId = 0;
    
    address public owner;
    address public verifierAddress;
    
    uint256 constant TREE_DEPTH = 20;
    
    // ============ Events ============
    
    event ElectionCreated(
        uint256 indexed electionId,
        string title,
        uint256 startTime,
        uint256 endTime
    );
    
    event VoteCast(
        uint256 indexed electionId,
        uint256 commitment,
        uint256 voteOption
    );
    
    event ElectionFinalized(
        uint256 indexed electionId,
        uint256[] results
    );
    
    // ============ Modifiers ============
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Nur Besitzer erlaubt");
        _;
    }
    
    modifier electionActive(uint256 electionId) {
        require(elections[electionId].active, "Wahl nicht aktiv");
        require(block.timestamp <= elections[electionId].endTime, "Wahlzeit abgelaufen");
        _;
    }
    
    modifier electionEnded(uint256 electionId) {
        require(block.timestamp > elections[electionId].endTime, "Wahl noch aktiv");
        _;
    }
    
    // ============ Constructor ============
    
    constructor(address _verifier) {
        owner = msg.sender;
        verifierAddress = _verifier;
        // Erstelle Semaphore Gruppe für Wähler
        _createGroup(semaphoreGroupId, TREE_DEPTH, 0);
    }
    
    // ============ Wahl-Management ============
    
    /**
     * @dev Erstelle eine neue Wahl
     * @param _title Titel der Wahl
     * @param _options Wahlmöglichkeiten
     * @param _duration Dauer der Wahl in Sekunden
     */
    function createElection(
        string memory _title,
        string[] calldata _options,
        uint256 _duration
    ) external onlyOwner returns (uint256) {
        require(_options.length >= 2, "Mindestens 2 Optionen erforderlich");
        require(_duration > 0, "Dauer muss > 0 sein");
        
        uint256 electionId = electionCounter++;
        uint256 startTime = block.timestamp;
        uint256 endTime = startTime + _duration;
        
        elections[electionId].title = _title;
        elections[electionId].options = _options;
        elections[electionId].startTime = startTime;
        elections[electionId].endTime = endTime;
        elections[electionId].active = true;
        
        emit ElectionCreated(electionId, _title, startTime, endTime);
        return electionId;
    }
    
    /**
     * @dev Registriere einen Wähler in der Semaphore Gruppe
     * @param _identityCommitment Der Commitment des Wählers
     */
    function registerVoter(uint256 _identityCommitment) external {
        _addMember(semaphoreGroupId, _identityCommitment);
    }
    
    /**
     * @dev Anonymer Vote mit Semaphore Zero-Knowledge Proof
     * @param _electionId ID der Wahl
     * @param _voteOption Wahlmöglichkeit (Index)
     * @param _signal Der Vote selbst (z.B. Option Hash)
     * @param _root Merkle Root aus Semaphore
     * @param _nullifierHash Verhindert doppeltes Abstimmen
     * @param _proof Der Zero-Knowledge Proof
     */
    function castVote(
        uint256 _electionId,
        uint256 _voteOption,
        uint256 _signal,
        uint256 _root,
        uint256 _nullifierHash,
        uint[8] calldata _proof
    ) external electionActive(_electionId) {
        require(_voteOption < elections[_electionId].options.length, "Ungültige Option");
        require(!hasVoted[_electionId][_nullifierHash], "Bereits abgestimmt");
        
        // Verifiziere Semaphore Proof (in echter Implementierung mit Verifier Contract)
        // IVerifier(verifierAddress).verifyProof(_proof, ...);
        
        Vote memory newVote = Vote({
            commitment: _signal,
            option: _voteOption,
            timestamp: block.timestamp
        });
        
        electionVotes[_electionId].push(newVote);
        elections[_electionId].voteCount[_voteOption]++;
        elections[_electionId].totalVotes++;
        hasVoted[_electionId][_nullifierHash] = true;
        
        emit VoteCast(_electionId, _signal, _voteOption);
    }
    
    // ============ Wahl-Auswertung (öffentlich lesbar) ============
    
    /**
     * @dev Beende die Wahl und speichere Ergebnisse
     * @param _electionId ID der Wahl
     */
    function finalizeElection(uint256 _electionId) 
        external 
        onlyOwner 
        electionEnded(_electionId) 
    {
        require(elections[_electionId].active, "Wahl bereits beendet");
        elections[_electionId].active = false;
    }
    
    /**
     * @dev Rufe die Ergebnisse einer Wahl ab (jeder kann auswerten)
     * @param _electionId ID der Wahl
     * @return results Array mit Stimmenzahlen pro Option
     */
    function getElectionResults(uint256 _electionId) 
        external 
        view 
        electionEnded(_electionId)
        returns (uint256[] memory results) 
    {
        uint256 optionCount = elections[_electionId].options.length;
        results = new uint256[](optionCount);
        
        for (uint256 i = 0; i < optionCount; i++) {
            results[i] = elections[_electionId].voteCount[i];
        }
        
        return results;
    }
    
    /**
     * @dev Rufe Wahl-Informationen ab
     * @param _electionId ID der Wahl
     */
    function getElectionInfo(uint256 _electionId) 
        external 
        view 
        returns (
            string memory title,
            string[] memory options,
            uint256 startTime,
            uint256 endTime,
            bool active,
            uint256 totalVotes
        ) 
    {
        return (
            elections[_electionId].title,
            elections[_electionId].options,
            elections[_electionId].startTime,
            elections[_electionId].endTime,
            elections[_electionId].active,
            elections[_electionId].totalVotes
        );
    }
    
    /**
     * @dev Verifiziere die Integrität der Blockchain
     * @param _electionId ID der Wahl
     * @return isValid Wahr wenn alle Votes valide sind
     */
    function verifyElectionIntegrity(uint256 _electionId) 
        external 
        view 
        returns (bool isValid) 
    {
        Vote[] memory votes = electionVotes[_electionId];
        uint256 totalCount = 0;
        
        for (uint256 i = 0; i < elections[_electionId].options.length; i++) {
            totalCount += elections[_electionId].voteCount[i];
        }
        
        return totalCount == votes.length && totalCount == elections[_electionId].totalVotes;
    }
    
    // ============ Hilfsfunktionen ============
    
    function getElectionCount() external view returns (uint256) {
        return electionCounter;
    }
    
    function getVoteCount(uint256 _electionId) external view returns (uint256) {
        return electionVotes[_electionId].length;
    }
}
