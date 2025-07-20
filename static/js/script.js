/**
 * scripts.js - Scripts principaux pour CyberGuard
 * Contient les fonctionnalités communes à toutes les pages
 */

// =============================================
// FONCTIONS UTILITAIRES
// =============================================

/**
 * Affiche le nom du fichier sélectionné dans un input file
 * @param {string} inputId - ID de l'input file
 * @param {string} displayId - ID de l'élément où afficher le nom
 */
function displayFileName(inputId, displayId) {
    const fileInput = document.getElementById(inputId);
    const fileDisplay = document.getElementById(displayId);
    
    if (fileInput && fileDisplay) {
        fileInput.addEventListener('change', function() {
            fileDisplay.textContent = this.files.length > 0 
                ? this.files[0].name 
                : 'Aucun fichier sélectionné';
            
            // Ajout d'une classe pour feedback visuel
            if (this.files.length > 0) {
                fileDisplay.classList.add('text-success', 'fw-bold');
            } else {
                fileDisplay.classList.remove('text-success', 'fw-bold');
            }
        });
    }
}

/**
 * Ferme automatiquement les alerts après un délai
 * @param {number} delay - Délai en millisecondes (par défaut 5s)
 */
function autoDismissAlerts(delay = 5000) {
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, delay);
    });
}

// =============================================
// GESTION DE LA NAVBAR
// =============================================

/**
 * Anime la navbar au scroll
 */
function setupNavbarScrollEffect() {
    const navbar = document.querySelector('.navbar');
    if (!navbar) return;

    let lastScroll = 0;
    const navbarHeight = navbar.offsetHeight;

    window.addEventListener('scroll', () => {
        const currentScroll = window.pageYOffset;
        
        // Effet de réduction au scroll vers le bas
        if (currentScroll > lastScroll && currentScroll > navbarHeight) {
            navbar.style.transform = 'translateY(-100%)';
        } else {
            navbar.style.transform = 'translateY(0)';
        }

        // Ajout d'une ombre quand on scroll
        if (currentScroll > 50) {
            navbar.style.boxShadow = '0 4px 12px rgba(0, 0, 0, 0.1)';
            navbar.style.background = 'rgba(255, 255, 255, 0.98)';
        } else {
            navbar.style.boxShadow = 'none';
            navbar.style.background = 'var(--white)';
        }

        lastScroll = currentScroll;
    });
}

/**
 * Met en surbrillance l'élément actif de la navbar
 */
function highlightActiveNavItem() {
    const currentPath = window.location.pathname.split('/').pop() || 'index';
    const navItems = document.querySelectorAll('.nav-link');
    
    navItems.forEach(item => {
        const itemPath = item.getAttribute('href').split('/').pop();
        
        // Correspondance approximative pour les pages
        if (currentPath.includes(itemPath)) {
            item.classList.add('active');
            
            // Animation d'indicateur
            const indicator = document.createElement('div');
            indicator.className = 'nav-indicator';
            item.appendChild(indicator);
            
            // Animation au hover
            item.addEventListener('mouseenter', () => {
                indicator.style.width = '100%';
            });
            
            item.addEventListener('mouseleave', () => {
                indicator.style.width = '50%';
            });
        }
    });
}

// =============================================
// INITIALISATION
// =============================================

document.addEventListener('DOMContentLoaded', function() {
    console.log('CyberGuard - Initialisation des scripts');
    
    // 1. Activer les tooltips Bootstrap
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(tooltipTriggerEl => {
        return new bootstrap.Tooltip(tooltipTriggerEl, {
            trigger: 'hover focus',
            animation: true
        });
    });

    // 2. Gestion des messages flash
    autoDismissAlerts();

    // 3. Configuration de la navbar
    setupNavbarScrollEffect();
    highlightActiveNavItem();

    // 4. Initialisation des sélecteurs de fichiers
    displayFileName('logFile', 'logFileDisplay');
    displayFileName('file', 'fileDisplay');
    
    // 5. Effet de parallaxe pour le header (optionnel)
    const header = document.querySelector('.hero-section');
    if (header) {
        window.addEventListener('scroll', () => {
            const scrollValue = window.scrollY;
            header.style.backgroundPositionY = `${scrollValue * 0.5}px`;
        });
    }
});

// =============================================
// ANIMATIONS PERSONNALISÉES
// =============================================

/**
 * Anime les éléments lorsqu'ils apparaissent à l'écran
 */
function setupScrollAnimations() {
    const animateElements = document.querySelectorAll('.animate-on-scroll');
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('animated');
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.1 });
    
    animateElements.forEach(el => observer.observe(el));
}

/**
 * Ajoute un effet de "pulse" aux éléments importants
 */
function setupPulseEffects() {
    const importantElements = document.querySelectorAll('.pulse-effect');
    
    importantElements.forEach(el => {
        el.addEventListener('mouseenter', () => {
            el.style.animation = 'pulse 1.5s infinite';
        });
        
        el.addEventListener('mouseleave', () => {
            el.style.animation = 'none';
        });
    });
}

// Initialisation des animations
if (document.readyState === 'complete') {
    setupScrollAnimations();
    setupPulseEffects();
} else {
    window.addEventListener('load', () => {
        setupScrollAnimations();
        setupPulseEffects();
    });
}